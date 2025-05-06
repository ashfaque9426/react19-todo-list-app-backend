// import express.js framework.
import express from 'express';
// create an instance of express.js server.
const app = express();

// import jwt package which is used to generate and verify json web tokens.
import jwt from 'jsonwebtoken';

// import dotenv package which is used to load environment variables from .env file.
import dotenv from 'dotenv';
// initilaizing config for dotenv to use environment vairables from .env file.
dotenv.config();

// import cors middleware for allow resource sharing to a different domain.
import cors from 'cors';

// import custom middleware and utility functions and other imports
import { addTodoRecord, deleteTodoRecord, generateAccessToken, getAllTodoDates, getFilteredTodoList, getTodoRecord, login, logout, modifyTodoRecord, processErrStr, register, updatePassword, verifyEmail } from './utilities.js';
import verifyJWT from './custom-middleware.js';
// apply cors middleware to enable cors origin requests.
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// import cookie-parser middleware to parse cookies from the request.
import cookieParser from 'cookie-parser';
app.use(cookieParser());

// parse the incoming requests to work with json paylods for post, put and patch requests.
app.use(express.json());

// define the port for express.js server.
const port = process.env.PORT || 5000;

// default gateway path for get request to check if the server is runnig properly.
app.get('/', (req, res) => res.send("Todo List Backend Server is running now."));

// register user to the mysql database express.js api.
app.post('/api/register-user', async (req, res) => {
    try {
        // destructure the properties from req.body object
        const { userName, userEmail, userPassword } = req.body;

        // if any destructured variable is missing send error message
        if (!userName || !userEmail || !userPassword) {
            return processErrStr(res, "All field params (userName, userEmail, userPassword) are required for registration  process.", "succMsg");
        }

        //  destructure userData and errMsg properties from the retrun value ofject of register function
        const { succMsg, errMsg } = await register(userName, userEmail, userPassword);

        // if user already exists then set a status code 409 otherwise 500 with the error message.
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if userData is available then send the userData
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if anything unexpected happened and unable to get userdata and error message the send the bellow error message
        return processErrStr(res, "Unexpected error occured during user registration process. Please try again later.", "succMsg");
    } catch (err) {
        // if any error message occured after calling the during registration process then print the error message to the console and send the message to the client with status code 500
        console.error("Registration error:", err);
        return processErrStr(res, "Unexpected Server error occured during user registration process. Please try again later.", "succMsg");
    }
});

// verify user email api
app.post('/api/verify-email', async (req, res) => {
    try {
        // get the token from query string
        const token = req.query.token;

        // check if token is available or not
        if (!token) return processErrStr(res, "Token is required for email verification process.", "succMsg");

        // verify the token and get the success message or error message
        const { succMsg, errMsg } = await verifyEmail(token);

        // if error message found then send the error message to client
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        } else if (succMsg) {
            // if success message found then send the success message to the client
            return res.status(200).json({ succMsg, errMsg: null });
        }

        // if any unexpected error occures.
        return processErrStr(res, "Unexpected error during email verification. Please try again later.", "succMsg");
    } catch (err) {
        // if any error message occured after calling the during registration process then print the error message to the console and send the message to the client with status code 500
        console.error("Registration error:", err);
        return processErrStr(res, "Unexpected Server error occured during email verification process. Please try again later.", "succMsg");
    }
});

// forgot password api
app.post('/api/forgot-password', async (req, res) => {
    try {
        // get the user email from req.body object
        const { userEmail } = req.body;

        // check if user email is available or not
        if (!userEmail) {
            return processErrStr(res, "userEmail is required for forgot password process.", "succMsg");
        }

        // send the email to the user for forgot password
        const { succMsg, errMsg } = await forgotPassword(userEmail);

        // if error message found then send the error message to client
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }
        // if success message found then send the success message to the client
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }
        
        // if any unexpected error occures.
        return processErrStr(res, "Unexpected error occured during sending email for forgot password.", "succMsg");
    } catch (err) {
        console.error("Forgot Password error:", err);
        return processErrStr(res, "Unexpected Server error occured during forgot password process. Please try again later.", "succMsg");
    }
});

// update password api.
app.patch('/api/update-password', async (req, res) => {
    try {
        // retirve the values
        const { token, newPassword }  = req.body;

        // check all values
        if (!token || !newPassword) {
            return processErrStr(res, "All fields (JWT Token, newPassword) values are required for updating password.", "succMsg");
        }

        // update the password.
        const { succMsg, errMsg } = await updatePassword(token, newPassword);

        // if error message found
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if success message is returned then send the succes message.
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if unexpected error occures.
        return processErrStr(res, "Unexpected error occured during updating password.", "succMsg");
    } catch (err) {
        // if any error message occured after calling the during registration process then print the error message to the console and send the message to the client with status code 500
        console.error("Password Update error:", err);
        return processErrStr(res, "Unexpected Server error occured during password update process. Please try again later.", "succMsg");
    }
});

// user login api
app.patch('/api/user-login', async (req, res) => {
    try {
        // retrive the values from req.body object
        const { userEmail, userPassword } = req.body;

        // check all values
        if (!userEmail || !userPassword) {
            return processErrStr(res, "All fields (userEmail, userPassword) are required for login.", "userData");
        }

        // login to database to get the credential secret
        const { userData, errMsg } = await login(userEmail, userPassword, res);

        // if errMsg found
        if (errMsg) {
            return processErrStr(res, errMsg, "userData");
        }

        // if successfully logged in then retrun user credential data to client
        if (userData) {
            return res.status(201).json({ userData, errMsg: null });
        }

        // if unexpected error occures.
        return processErrStr(res, "Unexpected error occured during user login.", "userData");
    } catch (err) {
        console.error("User Login error:", err);
        return processErrStr(res, "Unexpected Server error occured during user login process. Please try again later.", "userData");
    }
});

// refresh token api
app.post('/api/refresh-access-token', async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return processErrStr(res, "Invalid Refresh Token.", "accessToken");

        const { accessToken, errMsg } = await generateAccessToken(res, refreshToken);

        if (errMsg) {
            return processErrStr(res, errMsg, "accessToken");
        }

        if (accessToken) {  
            return res.status(200).json({ accessToken, errMsg: null });
        }

        return processErrStr(res, "Unexpected server error occured during generating access token.", "accessToken");
    } catch (err) {
        console.error("Error while refreshing access token:", err);
        return processErrStr(res, "Unexpected Server error occured during generating access token. Please try again later.", "accessToken");
    }
});

// user logout api
app.patch('/api/user-logout', verifyJWT, async (req, res) => {
    try {
        // get the user email and refresh token from req.body object
        const { userEmail } = req.body;

        // check all values
        if (!userEmail || req.decoded.userEmail !== userEmail) {
            return processErrStr(res, `Invalid user email found. Unable to logout the user. `, "succMsg");
        }

        // logout user
        const { succMsg, errMsg } = await logout(userEmail, req, res);

        // if error occured during user logout process
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if user successfully logged out
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if unexpected error occures.
        return processErrStr(res, "Unexpected error occured during user logout.", "succMsg");
    } catch (err) {
        console.error("User logout error:", err);
        return processErrStr(res, "Unexpected Server error occured during user logout process. Please try again later.", "succMsg");
    }
});

// get todo records from database
app.get('/api/get-todo-records', verifyJWT, async (req, res) => {
    try {
        // store the value for user email, date, title
        const userId = req.query.userId;
        const date = req.query.date;
        const title = req.query.title;

        // if user id is not available
        if (!userId || req.decoded.userId !== userId) {
            return processErrStr(res, `${!userId ? "User id is required to get todo records" : "Invalid user id detected. Todo records access denied."}`, "dataArr");
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
            return processErrStr(res, "Unexpected error occured during getting user requested data. Please try again later.", "dataArr");
        }

        // destructure dataArr and errMsg from returened value.
        const { dataArr, errMsg } = returnedValue;

        // if error message occured send errMsg to client
        if (errMsg) {
            return processErrStr(res, errMsg, "dataArr");
        }

        // if data array of requrested data available send that to client
        if (dataArr) {
            return res.status(200).json({ dataArr, errMsg: null });
        }

        // if some unexpected error occured later send user the bellow error message.
        return processErrStr(res, "Unexpected error occured during getting user data. Please try again later.", "dataArr");

    } catch (err) {
        console.error("Fetching user data error:", err);
        return processErrStr(res, "Unexpected Server error occured during the fetch process of requested user data. Please try again later.", "dataArr");
    }
});

app.get('/api/get-todo-dates', verifyJWT, async (req, res) => {
    try {
        const userId = req.query.userId;
        if (!userId || req.decoded.userId !== userId) {
            return processErrStr(res, `${!userId ? "User id is required to get todo records" : "Invalid user id detected. Todo records access denied."}`, "dateArr");
        }

        const { dateArr, errMsg } = await getAllTodoDates(userId);

        if (errMsg) {
            return processErrStr(res, errMsg, "dateArr");
        }

        if (dateArr) {
            return res.status(200).json({ dataArr, errMsg: null });
        }

        return processErrStr(res, "Unexpected error occured during getting all user record's dates from the database table. Please try again later.", "dateArr");

    } catch (err) {
        console.error("Fetching todo dates error:", err);
        return processErrStr(res, "Unexpected Server error occured during the fetch process of requested todo dates. Please try again later.", "dateArr");
    }
});

// add todo record api
app.post('/api/add-todo-record', verifyJWT, async (req, res) => {
    try {
        // destructuring required parameter from req(request).body object
        const { date, title, description, time, status, userId } = req.body;

        // initial value check for null or undefined
        if (!date || !title || !description || !time || !status || !userId) {
            return processErrStr(res, "All field params (date, title, description, time, status, userId) are required for adding todo record.", "succMsg");
        }

        // check time format and status value to validate the format and status value which should be added to the database.
        const timeRegex = /^(0[1-9]|1[0-2]):[0-5][0-9] (AM|PM)$/

        if (!timeRegex.test(time)) {
            return processErrStr(res, "Time is format like (HH:MM AM/PM) is required for adding to the todo record.", "succMsg");
        }

        if (status !== "completed" || status !== "not completed") {
            return processErrStr(res, "Status value can only contain the string completed or not completed for adding to the todo record.", "succMsg");
        }

        // check if the user id is valid or not
        if (req.decoded.userId !== userId) {
            return processErrStr(res, "Invalid user id detected. Add Todo record access denied.", "succMsg");
        }

        // add the record to the database.
        const { succMsg, errMsg } = await addTodoRecord(date, title, description, time, status, userId);

        // if error message returned from addTodoRecord then return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if success message returned from addTodoRecord return the success message.
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if some unexpected error occured later send user the bellow error message.
        return processErrStr(res, "Unexpected error occured during adding user record. Please try again later.", "succMsg");
    } catch (err) {
        console.error("Error while adding todo record:", err);
        return processErrStr(res, "Unexpected Server error occured during adding todo record process. Please try again later.", "succMsg");
    }
});

// get todo record
app.get('/api/get-todo-record', verifyJWT, async (req, res) => {
    try {
        // initial data check
        const recordId = req.query.recordId;

        if (!recordId) {
            return processErrStr(res, "Record id paramater value is required for getting the specific record data.", "recordData");
        }

        // get the refresh token from cookies and check if the refresh token is available or not
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return processErrStr(res, "Invalid refresh token.", "recordData");
        }

        // decode the refresh token to get the user id and check if the user id is valid or not
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

        if (decoded.userId !== req.decoded.userId) {
            return processErrStr(res, "Invalid user id detected. Get Todo record access denied.", "recordData");
        }

        // get the record data else return error message
        const { recordData, errMsg } = await getTodoRecord(recordId);

        if (errMsg) {
            return processErrStr(res, errMsg, "recordData");
        }

        if (recordData) {
            return res.status(200).json({ recordData, errMsg: null });
        }

        return processErrStr(res, "Unexpected error occured during getting user record. Please try again later.", "recordData");
    } catch (err) {
        console.error("Error while adding todo record:", err);
        return processErrStr(res, "Unexpected Server error occured during getting todo record process. Please try again later.", "recordData");
    }
});

// modify todo record api
app.patch('/api/modify-todo-record', verifyJWT, async (req, res) => {
    try {
        // get the refresh token from cookies and check if the refresh token is available or not
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return processErrStr(res, "Invalid refresh token.", "recordData");
        }

        // decode the refresh token to get the user id and check if the user id is valid or not
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

        if (decoded.userId !== req.decoded.userId) {
            return processErrStr(res, "Invalid user id detected. Get Todo record access denied.", "recordData");
        }

        // destructure required values from req.body
        const { date, title, description, time, status, recordId } = req.body;

        // initial value check
        if (!date || !title || !description || !recordId || !time || !status) {
            return processErrStr(res, "All field params (date, title, description, time, status, recordId) are required for modifying todo record process.", "succMsg");
        }

        // check time format and status value to validate the format and status value which should be added to the database.
        const timeRegex = /^(0[1-9]|1[0-2]):[0-5][0-9] (AM|PM)$/

        if (!timeRegex.test(time)) {
            return processErrStr(res, "Time is format like (HH:MM AM/PM) is required for adding to the todo record.", "succMsg");
        }

        if (status !== "completed" || status !== "not completed") {
            return processErrStr(res, "Status value can only contain the string completed or not completed for adding to the todo record.", "succMsg");
        }

        // add the record to the database.
        const { succMsg, errMsg } = await modifyTodoRecord(date, title, description, recordId);

        // if error message returned from addTodoRecord then return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if success message returned from addTodoRecord return the success message.
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if some unexpected error occured later send user the bellow error message.
        return processErrStr(res, "Unexpected error occured during modifying user record. Please try again later.", "succMsg");
    } catch (err) {
        console.error("Error while modifying todo record:", err);
        return processErrStr(res, "Unexpected Server error occured during modifying todo record process. Please try again later.", "succMsg");
    }
});

// delete todo record api
app.delete('/api/delete-todo-record/:recordId', verifyJWT, async (req, res) => {
    try {
        // destructuring and initial check
        const { recordId } = req.params;

        if (!recordId) {
            return processErrStr(res, "Record id paramater value is required for getting the specific record data.", "succMsg");
        }

        // get the refresh token from cookies and check if the refresh token is available or not
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return processErrStr(res, "Invalid refresh token.", "recordData");
        }

        // decode the refresh token to get the user id and check if the user id is valid or not
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

        if (decoded.userId !== req.decoded.userId) {
            return processErrStr(res, "Invalid user id detected. Get Todo record access denied.", "recordData");
        }

        // delete the record data
        const { succMsg, errMsg } = await deleteTodoRecord(recordId);

        // if error occured return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg, "succMsg");
        }

        // if successfully deleted the record then return the success message
        if (succMsg) {
            return res.status(201).json({ succMsg, errMsg: null });
        }

        // if some unexpected error occured later send user the bellow error message.
        return processErrStr(res, "Unexpected error occured during deleting user record. Please try again later.", "succMsg");
    } catch (err) {
        console.error("Error while deleting todo record:", err);
        return processErrStr(res, "Unexpected Server error occured during deleting todo record process. Please try again later.", "succMsg");
    }
});

// start the express.js server on the specified port.
app.listen(port, () => console.log(`Todo List Backend Server is running on port: ${port}`));