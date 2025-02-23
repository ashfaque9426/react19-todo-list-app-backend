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

async function checkPassword(inputPassword, storedHash) {
    try {
        const isMatch = await bcrypt.compare(inputPassword, storedHash);
        if (isMatch) {
            console.log('Password is correct ✅');
        } else {
            console.log('Incorrect password ❌');
        }
        return isMatch;
    } catch (error) {
        console.error('Error comparing password:', error);
        return false;
    }
}

// login and register
export async function register(userName, userEmail, userPassword, recoveryStr) {
    // safeguard cheking all the parameters
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
                    PRIMARY KEY (id)
                );
            `;

        await pool.query(createTableQuery);

        // if existed return an error message user already existed
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_name = ? AND user_email = ?`, [userName, userEmail]);

        if (doesUserExist.length > 0) {
            return { errMsg: "User record already exists in the database so you can't be able to register with an existing record" };
        }

        // if not create the user and update the record then provide user the user secret along with other user credential information.
        const hashedPassword = await hashPassword(userPassword);

        const [result] = await pool.query(`INSERT INTO users(user_name, user_email, hashed_pass, recovery_str, log_in_Status) VALUES (?, ?, ?, ?, ?)`, [userName, userEmail, hashedPassword, recoveryStr, 1]);

        if (result.affectedRows > 0 && result?.insertId) {
            const payload = {
                userId: result.insertId,
                userName: userName,
                userEmail: userEmail,
            };
            const secret = jwt.sign(payload, process.env.USER_LOGIN_SECRET, { expiresIn: '1h' });

            return { userData: { userId: result.insertId, userEmail: userEmail, userName: userName, userSecret: secret } };
        } else {
            return { errMsg: 'Something went wrong while trying to create user record. Please try again later.' };
        }
    } catch (err) {
        // if error occures ahen provide the error message to the user console and return user the error message.
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }

}

// update password
export async function updatePassword(userEmail, newPassword, recoveryStr) {
    // safeguard cheking all the parameters
    if (!userEmail || !newPassword || !recoveryStr) {
        return { errMsg: "The parameter value for each userName, userEmail, newPassword, recoveryStr are required." };
    }

    // get the id, password and recovery string by user email from users table
    try {
        // if existed return an error message user already existed
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_email = ?`, [userEmail]);

        if (doesUserExist.length === 0) {
            return { errMsg: "User does not exist in the database so you can't be able to update the password for unregistered user." };
        }

        // if recovery string does not match with hashes password or user is logged in still then return error message
        if (doesUserExist[0].recovery_str !== recoveryStr) {
            return { errMsg: 'Your recovery string does not match with the saved record field. Please make sure that you are providing recovery string correctly.' };
        } else if (doesUserExist[0].log_in_Status === 1) {
            return { errMsg: 'You can not update the password while you are logged in. please log out first.' };
        }

        // update the new hashed password tot the proper field in the database
        const newHashedPassword = await hashPassword(newPassword);

        const [fieldUpdateData] = await pool.query(`UPDATE users SET hashed_pass = ? WHERE user_email = ?`, [newHashedPassword, userEmail]);

        if (fieldUpdateData?.affectedRows > 0 && fieldUpdateData?.changedRows > 0) {
            return { succMsg: 'Password updated successfully to the database field. Now you can log in using the new password.' };
        } else {
            return { errMsg: 'Something went wrong while updating the password. Please try again.' };
        }
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// login
export async function login(userEmail, userPassword) {
    // safeguard cheking all the parameters
    if (!userEmail || !userPassword) {
        return { errMsg: "The parameter value for each userName, userEmail, userPassword, recoveryStr are required." };
    }

    try {
        // get the user data from users table by user_email or if login log_in_Status is 1 then return the message user already logged in
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_email = ?`, [userEmail]);

        if (doesUserExist.length === 0) {
            return { errMsg: "User record does not exist in the database." };
        } else if (doesUserExist[0]?.log_in_Status === 1) {
            return { errMsg: "User already logged in." };
        }

        // if hashed password matches then change log_in_Status is to 1 and give the user user USER_LOGIN_SECRET else send error message
        const passwordMatched = await checkPassword(userPassword, doesUserExist[0].hashed_pass);

        if (passwordMatched) {
            const payload = {
                userId: doesUserExist[0].id,
                userName: doesUserExist[0].user_name,
                userEmail: userEmail,
            };
            const secret = jwt.sign(payload, process.env.USER_LOGIN_SECRET, { expiresIn: '1h' });

            return { userData: { userId: doesUserExist[0].id, userEmail: userEmail, userName: doesUserExist[0].user_name, userSecret: secret } };
        } else {
            return { errMsg: 'User password does not match. Please make sure you are providing the user email and password correctly first.' };
        }
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// logout
export async function logout(userEmail) {
    // param check
    if(!userEmail) {
        return { errMsg: "The parameter value for userEmail is required." };
    }

    try {
        // fetch the user data from database
        const [doesUserExist] = await pool.query(`SELECT log_in_Status FROM users WHERE user_email = ?`, [userEmail]);

        // if user not found or logged out already then retrun the error message
        if (doesUserExist.length === 0) {
            return { errMsg: "The user you are trying to log out does not exist in the database." };
        } else if (doesUserExist[0].log_in_Status === 0) {
            return { errMsg: "The user you are trying to log out is already logged out from his account." };
        }

        // now update the login status to the database.
        const [updateResult] = await pool.query(`UPDATE users SET log_in_Status = 0 WHERE user_email = ?`, [userEmail]);

        // if successfully updated the logged out field in the database then return the success message else the error message.
        if (updateResult?.affectedRows > 0 && updateResult?.changedRows > 0) {
            return { succMsg: "User logged out successfully." };
        } else {
            return { errMsg: "Something went wrong when trying to log out the user. Please try again." };
        }
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo list record for a user
export async function getTodoListRecord(userId) {
    // if user log_in_status is 1 then give the user back the record form todo_list_user_data table
    // otherwise return an error message

    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required." };

    try {
        const [rows] = await pool.query(`SELECT todo_list_user_data.id as 'ID', todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title', todo_description as 'Description', user_id as 'UserID'
FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND users.log_in_Status = 1`, [userId]);
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
    if ((!date && !title) || (date && title)) return { errMsg: "Only one, date or title parameter value is required as string." };
    else if ((date && typeof date !== 'string') || (title && typeof title !== 'string')) return { errMsg: "date and time parameter values are required as strings." };
    else if (date && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };

    let queryStr = `SELECT todo_list_user_data.id as 'ID', todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title', todo_description as 'Description', user_id as 'UserID'
FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id `;

    // set the initial param array
    const params = [];

    // update the query string and push values to params
    if (date) {
        queryStr += `WHERE todo_list_user_data.todo_date = ? AND users.log_in_Status = 1`;
        params.push(date);
    } else if (title) {
        queryStr += `WHERE todo_list_user_data.todo_title = ? AND users.log_in_Status = 1`;
        params.push(title);
    } else {
        queryStr += `WHERE todo_list_user_data.user_id = ? AND users.log_in_Status = 1`;
        params.push(userId);
    }

    // try to query to the database if get the result then return the value or return an error message
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

// modify todoList record
export async function modifyTodoRecord(date, title, description, recordId) {
    // check all parameter values otherwise return an error message
    if (!date || !title || !description || !recordId) return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str>, recordId<num> all parameter values are quired." };
    else if (!date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };
    else if (isNaN(recordId)) return { errMsg: "recordId parameter value as a number required." };

    // if log_in_status is 1 then modify the current record of todo_list_user_data table by id field
    try {
        const [updateResult] = await pool.query(`UPDATE todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id SET todo_date = ?, todo_title = ?, todo_description = ? WHERE todo_list_user_data.id = ? AND users.log_in_Status = 1`, [date, title, description, recordId]);

        if (updateResult?.affectedRows > 0 && updateResult?.changedRows > 0) {
            return { succMsg: "Your todo list record updated successfully in the database." }
        } else {
            return { errMsg: "Something went wrong while trying to update the database record. Please try again." };
        }
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

// error message
export async function processErrStr(res, errMsg, msgStr, statusCodeOne) {
    if (typeof errMsg === "string" && errMsg.includes(msgStr)) {
        return res.status(statusCodeOne).json({ errMsg });
    } else {
        return res.status(500).json({ errMsg });
    }
}