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
import { addTodoRecord, deleteTodoRecord, getFilteredTodoList, getTodoRecord, login, logout, modifyTodoRecord, processErrStr, register, updatePassword } from './utilities.js';
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
            return res.status(400).json({ errMsg: "All field params (userName, userEmail, userPassword, recoveryStr) are required." });
        }

        //  destructure userData and errMsg properties from the retrun value ofject of register function
        const { userData, errMsg } = await register(userName, userEmail, userPassword, recoveryStr);

        // if user already exists then set a status code 409 otherwise 500 with the error message.
        if (errMsg) {
            return processErrStr(res, errMsg);
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
            return processErrStr(res, errMsg);
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
            return processErrStr(res, errMsg);
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
            return processErrStr(res, errMsg);
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
            return processErrStr(res, errMsg);
        }

        // if data array of requrested data available send that to client
        if (dataArr) {
            return res.status(200).json({ dataArr });
        }

        // if some unexpected error occured later send user the bellow error message.
        return res.status(500).json({ errMsg: "Unexpected error occured during getting user data. Please try again later." });

    } catch (err) {
        console.error("Fetching user data error:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during the fetch process of requested user data. Please try again later." });
    }
});

// add todo record api
app.post('/add-todo-record', verifyJWT, async (req, res) => {
    try {
        // destructuring required parameter from req(request).body object
        const { date, title, description, userId } = req.body;

        // initial value check for null or undefined
        if (!date || !title || !description || !userId) {
            return res.status(400).json({ errMsg: "All field params (date, title, description, userId) are required." });
        }

        // add the record to the database.
        const { succMsg, errMsg } = await addTodoRecord(date, title, description, userId);

        // if error message returned from addTodoRecord then return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg);
        }

        // if success message returned from addTodoRecord return the success message.
        if (succMsg) {
            return res.status(201).json({ succMsg });
        }

        // if some unexpected error occured later send user the bellow error message.
        return res.status(500).json({ errMsg: "Unexpected error occured during addding user record. Please try again later." });
    } catch (err) {
        console.error("Error while adding todo record:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during adding todo record process. Please try again later." });
    }
});

// get todo record
app.get('/get-todo-record', verifyJWT, async (req, res) => {
    try {
        // initial data check
        const recordId = req.query.recordId;

        if (!recordId) {
            return res.status(400).json({ errMsg: "Record id paramater value is required for getting the specific record data." });
        }

        // get the record data else return error message
        const { recordData, errMsg } = await getTodoRecord(recordId);

        if (errMsg) {
            return processErrStr(res, errMsg);
        }

        if (recordData) {
            return res.status(200).json({ recordId });
        }

        return res.status(500).json({ errMsg: "Unexpected error occured during getting user record. Please try again later." });
    } catch (err) {
        console.error("Error while adding todo record:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during adding todo record process. Please try again later." });
    }
});

// modify todo record api
app.patch('/modify-todo-record', verifyJWT, async (req, res) => {
    try {
        // destructure required values from req.body
        const { date, title, description, recordId } = req.body;

        // initial value check
        if (!date || !title || !description || !recordId) {
            return res.status(400).json({ errMsg: "All field params (date, title, description, recordId) are required." });
        }

        // add the record to the database.
        const { succMsg, errMsg } = await modifyTodoRecord(date, title, description, recordId);

        // if error message returned from addTodoRecord then return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg);
        }

        // if success message returned from addTodoRecord return the success message.
        if (succMsg) {
            return res.status(201).json({ succMsg });
        }

        // if some unexpected error occured later send user the bellow error message.
        return res.status(500).json({ errMsg: "Unexpected error occured during modifying the user record. Please try again later." });
    } catch (err) {
        console.error("Error while modifying todo record:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during modifying todo record process. Please try again later." });
    }
});

// delete todo record api
app.delete('/delete-todo-record/:recordId', verifyJWT, async (req, res) => {
    try {
        // destructuring and initial check
        const { recordId } = req.params;

        if (!recordId) {
            return res.status(400).json({ errMsg: "Record id paramater value is required for getting the specific record data." });
        }

        // delete the record data
        const { succMsg, errMsg } = await deleteTodoRecord(recordId);

        // if error occured return the error message.
        if (errMsg) {
            return processErrStr(res, errMsg);
        }

        // if successfully deleted the record then return the success message
        if (succMsg) {
            return res.status(201).json({ succMsg });
        }

        // if some unexpected error occured later send user the bellow error message.
        return res.status(500).json({ errMsg: "Unexpected error occured during deleting the user record. Please try again later." });
    } catch (err) {
        console.error("Error while deleting todo record:", err);
        return res.status(500).json({ errMsg: "Unexpected Server error occured during deleting todo record process. Please try again later." });
    }
});

// start the express.js server on the specified port.
app.listen(port, () => console.log(`Todo List Backend Server is running on port: ${port}`));