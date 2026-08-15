# Blogging Website Version 2.0

> **Fork notice.** This repository is a fork of
> [Prashant0664/Blog-website](https://github.com/Prashant0664/Blog-website),
> maintained here by our team. All credit for the original project goes to its
> upstream authors. See [Team setup](#team-setup) below for how to run it locally.

*For **Hacktoberfest** please refer [Contributing.md](https://github.com/Prashant0664/Blog-website/blob/master/CONTRIBUTING.md)* <br/>

For older version checkout the branch named *version1*

## Table of Contents
- [Introduction](#introduction)
- [New Features](#new-features)
- [Demo](#demo-link)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

---

## Introduction
Welcome to the Blogging Website project! This is a web application built using the MERN (MongoDB, Express.js, React.js, Node.js) stack. It allows users to create and manage their blogs, post projects, follow other users, comment on blogs, save content, bookmark blogs, like blogs and a lot more. The application also includes features such as email verification for user registration and Redux for state management.

---

## New Features:
🔥 **Like:** Users can now like Blogs and can see their liked blogs in profile.
🔥 **Filter:** User can now filter the content from dropdown menu below Navbar.
🔥 **Share:** User can now share blogs on social media using share button.
🔥 **Use of Params:** Blog Article now use params decreasing the coupling and increasing speed.
🔥 **Optimised:** More optimised than ever.
🔥 **User Frinedly:** More user friendly tha ever.

---

## Demo Link: 

Full Demo Video Drive link: [https://drive.google.com/file/d/1zPDw9Q28q-86CVlG62k5363gzIeGL7YX/view?usp=sharing
](https://drive.google.com/file/d/1As5DVfGSCfBOT9dqbX7MIYm69XllfGra/view?usp=sharing)

---


## Features
Here are some of the key features of this Blogging Website:

🔥 **User Authentication and Profiles:** Users can create and manage their profiles, with email verification for account security.

🔥 **Blogging:** Users can create and publish their blogs with rich text formatting.

🔥 **Sharing:** Users can share any blogs on social media platforms;

🔥 **Filter Blogs:** Users can search other users and filter content according to category.

🔥 **Project Posting:** Users can share and showcase their projects on their profile.

🔥 **Social Features:** Users can follow other users, comment on blogs, and save, like and bookmark content they like.

🔥 **Responsive Design:** The website is designed to work seamlessly on various screen sizes and devices.

🔥 **Secure:** The application follows best practices for security, including password hashing and user authentication.

🔥 **Content Management:** Users can easily edit, delete, or download their own posts.

---

## Technologies Used
The Blogging Website is built using the following technologies:

- **MERN Stack:**
  <br/>
  💫 MongoDB: A NoSQL database used to store user data, blogs, and other application data. <br/>
  💫 Express.js: A Node.js web application framework used for building the server.<br/>
  💫 React.js: A JavaScript library for building the user interface.<br/>
  💫 Node.js: A JavaScript runtime used for server-side code execution.<br/>

- **Additional Technologies:**<br/>
  💫 Redux: Used for state management within the React application.<br/>
  💫 Nodemailer: Used for email verification and sending email notifications.<br/>

---

## Getting Started
To set up this project locally, follow the instructions below.

### Prerequisites
Before you begin, make sure you have the following installed on your system:
- Node.js and npm (Node Package Manager)
- Git

### Installation
(Request: **Please Star⭐️ the Repo or follow [github](https://github.com/Prashant0664/) if you find this project interesting😁!** <br/>)
1. Clone this GitHub repository to your local machine:
   ```
   git clone https://github.com/Prashant0664/All-Blogs-V2.git
   ```

2. Change into the project directory:
   ```
   cd Blog-website
   ```

3. Install the backend dependencies:
   ```
   cd backend
   npm install
   ```

4. Install the frontend dependencies:
   ```
   cd ../client
   npm install
   ```

5. Set up your MongoDB database and configure the connection details in the backend's `.env` file.

_IMP: Seperate setup of both frontend and backend is given in *client* and *backend* folders *Readme.md*_

6. Start the backend server:
   ```
   cd ../backend
   npm start
   ```

7. Start the frontend development server:
   ```
   cd ../client
   npm start
   ```

8. Open your web browser and navigate to `http://localhost:3000` to access the Blogging Website.

---

## Team setup

Steps for teammates cloning this fork.

### 1. Environment files

Both `backend/.env` and `client/.env` are **gitignored** and will not arrive with
the clone. Copy the templates and fill them in:

```bash
cp backend/.env.example backend/.env
cp client/.env.example client/.env
```

Ask the project owner for the real values — send them through a password manager
or another private channel, **never** in a GitHub issue, PR, or chat message.

`client/.env` is read by Create React App only at startup, so restart
`npm start` after editing it.

### 2. Run both servers

```bash
cd backend && npm install && npm start   # http://localhost:5002
cd client  && npm install && npm start   # http://localhost:3000
```

### 3. Seed sample content (optional)

A fresh database has no posts. To create one sample author and one sample blog
post:

```bash
cd backend && node seed/sampleblog.js
```

The script is safe to re-run and prints the seeded author's login details. Edit
the `AUTHOR` / `POST` objects at the top of `seed/sampleblog.js` to add more.

### Notes

- `category` on a post must be one of `food`, `travelling`, `lifestyle`, `tech`
  (enforced by the schema in `backend/models/Post.js`).
- Google sign-in needs `http://localhost:5002/auth/google/callback` registered as
  an authorized redirect URI in the Google Cloud console.
- Signup sends an OTP by email, so `EMAIL_ID` / `PASS` must be set for
  registration to complete. `PASS` is a Gmail **App Password**.
- If everyone shares one MongoDB Atlas connection string, you are all working
  against the **same database** — one person's test data is visible to everyone.

---

## Usage
You can now use the Blogging Website to create, like, save, share, and discover blogs, projects, and much more. Use Google Signin or Register an account, verify your email, and start enjoying the features of the application.

---

## Contributing
**Please Star⭐️ the Repo or follow [github](https://github.com/Prashant0664/) if you find this project interesting😁!** <br/>
Contributions to this project are welcome! If you'd like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with clear and descriptive commit messages. (Installation and Setup has been Explained in [Getting-Started](#getting-started) )
4. Push your changes to your fork.
5. Submit a pull request to the main repository.
<br/>

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

### *Note: For any doubt or question you can open an issue. I will reply ASAP.*

Thank you for using and contributing to the Blogging Website project! If you have any questions or need assistance, please don't hesitate to reach out to the maintainers.