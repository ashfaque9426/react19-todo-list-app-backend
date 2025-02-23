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

// import custom middleware and utility functions and other imports
import { getFilteredTodoList, login, logout, processErrStr, register, updatePassword } from './utilities.js';
import verifyJWT from './custom-middleware.js';
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
        if (errMsg) {
            return processErrStr(res, errMsg, "User already exists", 409);
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

// update password api.
app.patch('/update-password', async (req, res) => {
    try {
        // retirve the values
        const { userEmail, newPassword, recoveryStr }  = req.body;

        // check all values
        if (!userEmail || !newPassword || !recoveryStr) {
            return res.status(400).json({ errMsg: "All fields (userName, userEmail, newPassword, recoveryStr) are required." });
        }

        // update the password.
        const { succMsg, errMsg } = await updatePassword(userEmail, newPassword, recoveryStr);

        // if error message found
        if (errMsg) {
            return processErrStr(res, errMsg, "User does not exist", 404);
        }

        // if success message is returned then send the succes message.
        if (succMsg) {
            return res.status(201).json({ succMsg });
        }

        // if unexpected error occures.
        return res.status(500).json({ errMsg: "Unexpected error occured during updating password." });
    } catch (err) {
        // if any error message occured after calling the during registration process then print the error message to the console and send the message to the client with status code 500
        console.error("Password Update error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during password update process. Please try again later." });
    }
});

// user login api
app.patch('/user-login', async (req, res) => {
    try {
        // retrive the values from req.body object
        const { userEmail, userPassword } = req.body;

        // check all values
        if (!userEmail || !userPassword) {
            return res.status(400).json({ errMsg: "All fields (userEmail, userPassword) are required." });
        }

        // login to database to get the credential secret
        const { userData, errMsg } = await login(userEmail, userPassword);

        // if errMsg found
        if (errMsg) {
            return processErrStr(res, errMsg, "password does not match", 401);
        }

        // if successfully logged in then retrun user credential data to client
        if (userData) {
            return res.status(201).json({ userData });
        }

        // if unexpected error occures.
        return res.status(500).json({ errMsg: "Unexpected error occured during user login." });
    } catch (err) {
        console.error("User Login error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during user login process. Please try again later." });
    }
});

// user logout api
app.patch('/user-logout', async (req, res) => {
    try {
        // retrieve the user eamil
        const { userEmail } = req.body;

        // check all values
        if (!userEmail) {
            return res.status(400).json({ errMsg: "All fields userEmail is required." });
        }

        // logout user
        const { succMsg, errMsg } = await logout(userEmail);

        // if error occured during user logout process
        if (errMsg) {
            return processErrStr(res, errMsg, "does not exist", 404);
        }

        // if user successfully logged out
        if (succMsg) {
            return res.status(201).json({ succMsg });
        }

        // if unexpected error occures.
        return res.status(500).json({ errMsg: "Unexpected error occured during logout." });
    } catch (err) {
        console.error("User logout error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during user logout process. Please try again later." });
    }
});

// get todo records from database
app.get('/get-todo-records', verifyJWT, async (req, res) => {
    try {
        // store the value for user email, date, title
        const userId = req.query.userId;
        const date = req.query.date;
        const title = req.query.title;

        // if user id is not available
        if (!userId) {
            return res.status(400).json({ errMsg: "User id parameter value is required." });
        }

        // initilialize empty returned value variable for later use case.
        let returnedValue;

        // if date is available fetch by date or if title is available fetch be titme else fetch all data that matches user id.
        if (date) {
            returnedValue = await getFilteredTodoList(userId, date, "");
        } else if (title) {
            returnedValue = await getFilteredTodoList(userId, "", title);
        } else {
            returnedValue = await getFilteredTodoList(userId, "", "");
        }

        // if unexpected error occures.
        if (!returnedValue) {
            return res.status(500).json({ errMsg: "Unexpected server error occured while tried to fetch user requested data. Please try again later." });
        }

        // destructure dataArr and errMsg from returened value.
        const { dataArr, errMsg } = returnedValue;

        // if error message occured send errMsg to client
        if (errMsg) {
            return processErrStr(res, errMsg, "required", 400);
        }

        // if data array of requrested data available send that to client
        if (dataArr) {
            return res.status(200).json({ dataArr });
        }

        // if some unexpected error occured later send user the bellow error message.
        return res.status(500).json({ errMsg: "Unexpected error occured during getting user data. Please try again later." });

    } catch (err) {
        console.error("Fetching user data error error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during the fetch process of requested user data. Please try again later." });
    }
});

// start the express.js server on the specified port.
app.listen(port, () => console.log(`Todo List Backend Server is running on port: ${port}`));