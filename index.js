import express from "express";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutos
  max: 10, // Máximo de 10 requisições por IP nesse período
  message: {
    success: false,
    message: "Muitas tentativas. Tente novamente em 5 minutos.",
  },
});

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());
const PORT = process.env.PORT || 10000;
const { SECRET_KEY } = process.env;
app.use(
  cors({
    origin: "https://fjapa.shop",
    credentials: true,
  })
);
const db = new PrismaClient();

const generateHash = async (password) => {
  return bcrypt.hash(password, 12);
};

try {
  if (!process.env.PORT || !process.env.SECRET_KEY) {
    throw new Error("Erro nas váriaveis de ambiente");
  }
} catch (error) {
  console.error(error.message);
  process.exit(1); // Encerra a aplicação com erro
}

// this endpoint is to create a new user
app.post("/user", async (req, res) => {
  const { name, email, password } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      error: "incomplete arguments",
    });
  }

  const verifyUser = await db.login.findFirst({
    where: {
      email,
    },
  });

  if (verifyUser) {
    return res.status(400).json({
      success: false,
      message: "Esse e-mail já está cadastrado!",
    });
  }

  const hashPass = await generateHash(password);
  const newUser = await db.login.create({
    data: {
      email,
      name,
      password: hashPass,
      ip: ip || "Erro ao capturar o IP",
    },
  });

  return res.status(201).json({
    success: true,
    message: "Usuário criado com sucesso!",
  });
});

// this endpoint is to verify credentials of access
app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: "incomplete arguments",
    });
  }

  const verifyUser = await db.login.findFirst({
    where: {
      email,
    },
  });

  if (!verifyUser) {
    return res.status(401).json({
      success: false,
      message: "E-mail não encontrado",
    });
  }

  const validatePass = await bcrypt.compare(password, verifyUser.password);

  if (!validatePass) {
    return res.status(401).json({
      success: false,
      message: "E-mail ou senha incorreta!",
    });
  } else {
    const payload = {
      id: verifyUser.id,
      name: verifyUser.name,
      email: verifyUser.email,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

    res.cookie("TOKEN", token).status(200).json({
      success: true,
      message: "Login realizado com sucesso!",
      token: `Bearer ${token}`,
    });
  }
});

// this is route private, required token jwt
app.get("/private", loginLimiter, async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Acesso negado, token não fornecido",
    });
  }

  try {
    const validateToken = jwt.verify(token, SECRET_KEY);
    return res.status(200).json({
      success: true,
      message: "Acesso autorizado a rota protegida!",
      user: {
        id: validateToken.id,
        name: validateToken.name,
        email: validateToken.email,
      },
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token inválido ou expirado!",
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
