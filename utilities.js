import pool from "./database.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

// hash password function
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
}

// login and register
export async function register(userName, userEmail, userPassword, recoveryStr) {
    if (!userName || !userEmail || !userPassword || !recoveryStr) {
        return { errMsg: "The parameter value for each userName, userEmail, userPassword, recoveryStr are required." };
    }

    // check if user record existed in users table
    try {
        const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT NOT NULL AUTO_INCREMENT,
                    user_name VARCHAR(256) NOT NULL,
                    user_email VARCHAR(256) NOT NULL,
                    hashed_pass  VARCHAR(256) NOT NULL,
                    recovery_str VARCHAR(256) NOT NULL,
                    log_in_Status TINYINT(1) NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                );
            `;

        await pool.query(createTableQuery);

        // if existed return an error message user already existed
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_name = ? AND user_email = ?`, [userName, userEmail]);

        if (doesUserExist.length > 0) {
            return { errMsg: "User record already existed in the database so you can't be able to register with an existing record" };
        }

        // if not create the user and update the record then provide user the user secret along with other user credential information.
        const hashedPassword = await hashPassword(userPassword);

        const [result] = await pool.query(`INSERT INTO users(user_name, user_email, hashed_pass, recovery_str, log_in_Status) VALUES (?, ?, ?, ?)`, [userName, userEmail, hashedPassword, recoveryStr, 1]);

        if (result.affectedRows > 0 && result?.insertId) {
            const payload = {
                userId: result.insertId,
                userName: userName,
                userEmail: userEmail,
            };
            const secret = jwt.sign(payload, process.env.USER_LOGIN_SECRET, { expiresIn: '1h' });

            return { userData: { userId: result.insertId, userEmail: userEmail, userName: userName, userSecret: secret } };
        } else {
            return { errMsg: 'Something went wrong while trying to create user record. Please try again later.' }
        }
    } catch (err) {
        // if error occures ahen provide the error message to the user console and return user the error message.
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }

}

// update password
export async function updatePassword(userEmail, newPassword, recoveryStr) {
    // get the id, password and recovery string by user email from users table
    // if recovery string matches then hash the password and update hashed_pass field by id field
}

// login
export async function login(userEmail, hashedPass) {
    // get the user data from users table by user_email
    // if login log_in_Status is 1 then return the message user already logged in
    // if hashed password matches then change log_in_Status is to 1 and give the user user USER_LOGIN_SECRET

}

// get todo list record for a user
export async function getTodoListRecord(userId) {
    // if user log_in_status is 1 then give the user back the record form todo_list_user_data table
    // otherwise return an error message

    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required." };

    try {
        const [rows] = await pool.query(`SELECT todo_list_user_data.id as 'ID', todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title', todo_description as 'Description', user_id as 'UserID'
FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ${userId} AND users.log_in_Status = 1`);
        return { dataArr: rows };
    }
    catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo list record for a user filtered by params
export async function getFilteredTodoList(userId, date = "", title = "") {
    // check the first parameter as a number available or not if not return error message
    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required." };

    // check only date or title parameter value is available as string and if date is available does it meet the regex format /^\d{4}-\d{2}-\d{2}/ if any of the bellow condition failed then return the error message
    if ((!date && !title) || (date && title)) return { errMsg: "Only date or title parameter value is required as string." };
    else if ((date && typeof date !== 'string') || (title && typeof title !== 'string')) return { errMsg: "date and time parameter values are required as strings." };
    else if (date && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };

    let queryStr = `SELECT todo_list_user_data.id as 'ID', todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title', todo_description as 'Description', user_id as 'UserID'
FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id `;

    const params = [];

    if (date) {
        queryStr += `WHERE todo_list_user_data.todo_date = ? AND users.log_in_Status = 1`;
        params.push(date);
    } else if (title) {
        queryStr += `WHERE todo_list_user_data.todo_title = ? AND users.log_in_Status = 1`;
        params.push(title);
    }

    try {
        const [rows] = await pool.query(queryStr, params);
        return { dataArr: rows };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// add totolist record
export async function addTodoRecord(date, title, description, userId) {
    // check all parameter values otherwise return an error message
    if (!date || !title || !description || !userId) return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str>, userId<num> all parameter values are quired." };
    else if (!date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };
    else if (isNaN(userId)) return { errMsg: "userId parameter value as a number required." };

    // if log_in_status is 1 then add the record to todo_list_user_data table
    try {
        const createTableQuery = `
                CREATE TABLE IF NOT EXISTS todo_list_user_data (
                    id INT NOT NULL AUTO_INCREMENT,
                    todo_date VARCHAR(256) NOT NULL,
                    todo_title VARCHAR(256) NOT NULL,
                    todo_description  VARCHAR(256) NOT NULL,
                    user_id INT NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
            `;

        await pool.query(createTableQuery);

        const [result] = await pool.query(`INSERT INTO todo_list_user_data (todo_date, todo_title, todo_description, user_id) SELECT ?, ?, ?, id FROM users WHERE id = ? AND log_in_Status = 1`, [date, title, description, userId]);
        return { insertionData: result }
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

const { insertionData, errMsg } = await addTodoRecord('2025-02-20', 'Gadget List', 'Iphone 15', 1);
console.log(insertionData, errMsg);

// modify todoList record
export async function modifyTodoRecord(date, title, description, recordId) {
    // check all parameter values otherwise return an error message
    if (!date || !title || !description || !recordId) return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str>, recordId<num> all parameter values are quired." };
    else if (!date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };
    else if (isNaN(recordId)) return { errMsg: "recordId parameter value as a number required." };

    // if log_in_status is 1 then modify the current record of todo_list_user_data table by id field
    try {
        const [result] = await pool.query(`UPDATE todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id SET todo_date = ?, todo_title = ?, todo_description = ? WHERE todo_list_user_data.id = ? AND users.log_in_Status = 1`, [date, title, description, recordId]);

        return { rowModificationInfo: result };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// detele todolist record
export async function deleteTodoRecord(recordId) {
    // check recordId patameter is a number type. if not return a error message.
    if(isNaN(recordId)) return { errMsg: "userId and recordId parameter value must be in number type" };

    // if log_in_status is 1 then delete the requested record of todo_list_user_data table by id field
    try {
        const [result] = await pool.query(`DELETE todo_list_user_data FROM todo_list_user_data JOIN users on todo_list_user_data.user_id = users.id WHERE todo_list_user_data.id = ? AND users.log_in_Status = 1`, [recordId]);

        return { rowDeletionInfo: result };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
    
}