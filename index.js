// import express.js framework.
import express from 'express';
// create an instance of express.js server.
const app = express();

// import dotenv package which is used to load environment variables from .env file.
import dotenv from 'dotenv';
// initilaizing config for dotenv to use environment vairables from .env file.
dotenv.config();

// import cors middleware for allow resource sharing to a different domain.
import cors from 'cors';
import { register } from './utilities.js';
// apply cors middleware to enable cors origin requests.
app.use(cors());

// parse the incoming requests to work with json paylods for post, put and patch requests.
app.use(express.json());

// define the port for express.js server.
const port = process.env.PORT || 5000;

// default gateway path for get request to check if the server is runnig properly.
app.get('/', (req, res) => res.send("Todo List Backend Server is running now."));

// register user to the mysql database express.js api.
app.post('/register-user', async (req, res) => {
    try {
        // destructure the properties from req.body object
        const { userName, userEmail, userPassword, recoveryStr } = req.body;

        // if any destructured variable is missing send error message
        if (!userName || !userEmail || !userPassword || !recoveryStr) {
            return res.status(400).json({ errMsg: "All fields (userName, userEmail, userPassword, recoveryStr) are required." });
        }

        //  destructure userData and errMsg properties from the retrun value ofject of register function
        const { userData, errMsg } = await register(userName, userEmail, userPassword, recoveryStr);

        // if user already exists then set a status code 409 otherwise 500 with the error message.
        if (errMsg && errMsg.includes("User already exists")) {
            return res.status(409).json({ errMsg });
        } else if (errMsg) {
            return res.status(500).json({ errMsg });
        }

        // if userData is available then send the userData
        if (userData) {
            return res.status(201).json({ userData });
        }

        // if anything unexpected happened and unable to get userdata and error message the send the bellow error message
        return res.status(500).json({ errMsg: "Unexpected error during registration." });
    } catch (err) {
        // if any error message occured after calling the during registration process then print the error message to the console and send the message to the client with status code 500
        console.error("Registration error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during user registration process. Please try again later." });
    }
});

// start the express.js server on the specified port.
app.listen(port, () => console.log(`Todo List Backend Server is running on port: ${port}`));