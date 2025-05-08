# 🦷 LOGIN BACKEND

> Um backend seguro e eficiente para autenticação de usuários em sistemas odontológicos.

---

## 🚀 Descrição

Este projeto é uma API RESTful em **Node.js** com **Express**, responsável por gerenciar cadastro, login e acesso protegido via JWT. Utiliza **Prisma** para acesso ao banco de dados **mongoDB**, **bcrypt** para hash de senhas, e **express-rate-limit** para proteção contra brute-force. Ideal para integração com frontends modernos (React, Vue, Angular) ou apps móveis.

---

## 🎯 Funcionalidades

- 📥 **Cadastro de Usuário**
- 🔐 **Login com JWT**
- 🔒 **Rotas Privadas Protegidas por Token**
- ⏱️ **Rate Limiting** (máx. 10 tentativas a cada 5 minutos)
- 🍪 **Uso de Cookies** para armazenar o token
- 🌐 **CORS** configurado para frontend específico

---

## 🛠️ Tecnologias

- **Node.js**
- **Express**
- **Prisma** (@prisma/client)
- **bcrypt**
- **jsonwebtoken**
- **express-rate-limit**
- **cookie-parser**
- **dotenv**
- **cors**

---

## 🚧 Pré-requisitos

- Node.js ≥ 16.x
- npm ou yarn

---

## 📝 Instalação

1. Clone o repositório
   ```bash
   git clone https://github.com/devFelipeMarcos/login-backend.git
   cd login-backend
   ```
