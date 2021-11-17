import express from "express";
import { MongoClient } from "mongodb";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import bcrypt, { compare } from "bcrypt";
dotenv.config();
import cors from "cors";
const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;
async function createConnection() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  return client;
}

app.get("/", async (request, response) => {
  response.send("please append the end points");
})
app.post("/users/forgot", async (request, response) => {
  const { email } = request.body;
  const currentTime = new Date();
  const expireTime = new Date(currentTime.getTime() + 5 * 60000);
  const client = await createConnection();
  const user = await client.db("resetflow").collection("passwords").find({ email: email }).toArray();
  if (user.length > 0) {
    const randomString = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    await client.db("resetflow").collection("passwords").updateOne({ email: email },
      {
        $set:
          { randomString: randomString, expireTime: expireTime }
      });
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
        clientId: process.env.OAUTH_CLIENTID,
        clientSecret: process.env.OAUTH_CLIENT_SECRET,
        refreshToken: process.env.OAUTH_REFRESH_TOKEN
      }
    });
    let mailOptions = {
      from: 'ranjithch137@gmail.com',
      to: email,
      subject: 'Reset Password link',
      html:
        '<a href = "https://password-reset-ranjith.netlify.app/retrieveAccount/' + email + '/' + randomString + '"> Reset Password Link</a>'
    };
    transporter.sendMail(mailOptions, function (err, data) {
      if (err) {
        response.send("Error " + err);
      } else {
        response.send({message:"Email sent successfully"});
      }
    });
  }
  else {
    response.send( {message:"This email is not registered"});
  }
})
app.get("/retrieveAccount/:email/:randomString", async (request, response) => {
  const currentTime = new Date();
  const { email, randomString } = request.params;
  const client = await createConnection();
  const user = await client.db("resetflow").collection("passwords").find({ email: email }).toArray();
  if (user.length > 0) {
    const randomStringInDB = user[0].randomString;
    if (randomString == randomStringInDB) {
      if (currentTime > user[0].expireTime) {
        response.send( {message:"link expired"} )
      } else {
        response.send({message:"retrieve account"});
      }

    } else {
      response.send( {message:"invalid authentication"} );
    }
  }
  else {
    response.send( {message:"Invalid account"});
  }
})
app.put("/resetPassword/:email/:randomString", async (request, response) => {
  const currentTime = new Date();
  const { email, randomString } = request.params;
  const { newPassword } = request.body;
  const client = await createConnection();
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(newPassword, salt);
  const user = await client.db("resetflow").collection("passwords").find({ email: email, randomString: randomString }).toArray();
  if (!user[0]) {
    response.send({message:"invalid url"});
  } else {
    const expireTime = user[0].expireTime;
    if (currentTime > expireTime) {
      response.send({ message: "link expired" });
    } else {
    const result = await client.db("resetflow").collection("passwords").updateOne({
      email: email,
      randomString: randomString
    },
      {
        $set: {
          password: hashedPassword
        },
        $unset: {
          randomString: "",
          expireTime: ""
        }
      });
    response.send({message:"password updated"});
  }
}
})
app.post("/users/SignUp", async (request, response) => {
  const { email, password } = request.body;
  const client = await createConnection();
  const user = await client.db("resetflow").collection("passwords").find({ email: email}).toArray()
  if (user.length > 0){
    response.send({message:"This email is already registered"})
  } else {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const result = await client.db("resetflow").collection("passwords").insertOne({ email: email, password: hashedPassword });
  response.send({message:'Sign up success. Click "Login" to use the account'});
  }
})
app.post("/users/Login", async (request, response) => {
  const { email, password } = request.body;
  const client = await createConnection();
  const user = await client.db("resetflow").collection("passwords").find({ email: email }).toArray();
  if (user.length > 0) {
    const passwordstoredindb = user[0].password;
    const loginFormPassword = password;
    const ispasswordmatch = await bcrypt.compare(loginFormPassword, passwordstoredindb);
    if (ispasswordmatch) {
      response.send({ message: "successful login!!!" });
    } else {
      response.send({ message: "invalid login" });
    }
  } else {
    response.send({ message: "invalid login" });
  }
})
app.listen(PORT, () => console.log("The server is started"));

