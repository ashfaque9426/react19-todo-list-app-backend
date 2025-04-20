import pool from "./database.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
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
export async function register(userName, userEmail, userPassword) {
    // safeguard cheking all the parameters
    if (!userName || !userEmail || !userPassword) {
        return { errMsg: "The parameter value for each userName, userEmail, userPassword are required." };
    }

    // check if user record existed in users table
    try {
        const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT NOT NULL AUTO_INCREMENT,
                    user_name VARCHAR(256) NOT NULL,
                    user_email VARCHAR(256) NOT NULL,
                    hashed_pass  VARCHAR(256) NOT NULL,
                    log_in_Status BOOLEAN NOT NULL DEFAULT 0,
                    email_varified BOOLEAN NOT NULL DEFAULT 0,
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

        // insert the user record to the database
        const [result] = await pool.query(`INSERT INTO users(user_name, user_email, hashed_pass) VALUES (?, ?, ?)`, [userName, userEmail, hashedPassword]);

        // if user record is created successfully then send the verification email to the user email address and return the success message
        if (result.affectedRows > 0 && result?.insertId) {
            const token = jwt.sign({ email: userEmail }, process.env.APP_SECRET, { expiresIn: '1h' });
            const verificationLink = `${process.env.SITE_DOMAIN}/api/verify-email?token=${token}`;

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.APP_EMAIL,
                    pass: process.env.APP_PASS,
                },
            });

            await transporter.sendMail({
                from: process.env.APP_EMAIL,
                to: userEmail,
                subject: "Verify Your Email For Todo List App",
                html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`
            });

            return { succMsg: `Verification mail has sent to user and User Record has been added to database successfully.` };
        } else {
            return { errMsg: 'Something went wrong while trying to create user record. Please try again later.' };
        }
    } catch (err) {
        // if error occures ahen provide the error message to the user console and return user the error message.
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

export async function verifyEmail(token) {
    try {
        // decode the given token and get the email from it
        const decoded = jwt.verify(token, process.env.APP_SECRET);
        const email = decoded.email;

        // update sql database column email_varified and mark the user as verified
        const [result] = await pool.query(`UPDATE users SET email_varified = 1 WHERE user_email = ?`, [email]);

        // if no rows were affected, it means the user was not found or already verified
        if (result.affectedRows === 0) {
            return { errMsg: "Update verification information failed. Please try again later." };
        }

        return { succMsg: 'Email verified successfully!' };
    } catch (err) {
        console.error("Invalid or expired token", err.message);
        return { errMsg: err.message };
    }
}

// update password
export async function updatePassword(token, newPassword) {
    try {
        const decoded = jwt.verify(token, process.env.APP_SECRETT);
        const email = decoded.email;
        // if existed return an error message user already existed
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_email = ?`, [email]);

        if (doesUserExist.length === 0 || doesUserExist[0].email_varified === 0) {
            return { errMsg: doesUserExist.length === 0 ? "User does not exist in the database so you can't be able to update the password for unregistered user." : "User Email is not verified yet." };
        } else if (doesUserExist[0].log_in_Status === 1) {
            return { errMsg: 'You can not update the password while you are still logged in. Please log out first to update password.' };
        }

        // update the new hashed password tot the proper field in the database
        const newHashedPassword = await hashPassword(newPassword);

        const [fieldUpdateData] = await pool.query(`UPDATE users SET hashed_pass = ? WHERE user_email = ?`, [newHashedPassword, doesUserExist[0].user_email]);

        if (fieldUpdateData?.affectedRows > 0 && fieldUpdateData?.changedRows > 0) {
            return { succMsg: 'Password updated successfully to the database field. Now you can log in using the new password.' };
        } else {
            return { errMsg: 'Something went wrong while updating the password. Please try again.' };
        }
    } catch (err) {
        console.error("Database error while updating password:", err.message);
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
        } else if (doesUserExist[0]?.log_in_Status === 1 || doesUserExist[0]?.email_varified === 0) {
            return { errMsg: doesUserExist[0]?.email_varified === 0 ? "User Email not verified yet." : "User already logged in." };
        }

        // if hashed password matches then change log_in_Status is to 1 and give the user user USER_LOGIN_SECRET and update the log in status in the database, else send error message
        const passwordMatched = await checkPassword(userPassword, doesUserExist[0].hashed_pass);

        if (passwordMatched) {
            await pool.query(`UPDATE users SET log_in_Status = 1 WHERE id = ?`, [doesUserExist[0].id]);

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
    if (date && title) return { errMsg: "Only one, date or title parameter value is required as string, not both at once." };
    else if ((date && typeof date !== 'string') || (title && typeof title !== 'string')) return { errMsg: `${(date ? 'date' : 'title')} parameter values is required as strings.` };
    if (date && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };

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
    if (typeof date !== 'string' || typeof title !== 'string' || typeof description !== 'string') return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str> parameter values are required." };
    if (typeof date === 'string' && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD, only YYYY-MM-DD date format required as a string." };
    if (isNaN(userId)) return { errMsg: "userId parameter value as a number required." };

    // if log_in_status is 1 then add the record to todo_list_user_data table and if table is not created already create the table first
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

        if (result.insertId && result.affectedRows > 0) {
            return { succMsg: "Todolist record added to the database successfully." }
        }
        
        return { errMsg: "Something went wrong while adding todolist record to the database. Please try again later." };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo record
export async function getTodoRecord(recordId) {
    // check all param values
    if (isNaN(recordId)) {
        return { errMsg: `recordId parameter value as a number is required.` };
    }

    // get the record and return it or return the error message
    try {
        const [rows] = await pool.query(`SELECT * FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.id = ? AND users.log_in_Status = 1`, [recordId]);
        return { recordData: rows[0] };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// modify todoList record
export async function modifyTodoRecord(date, title, description, recordId) {
    // check all parameter values otherwise return an error message
    if (typeof date !== 'string' || typeof title !== 'string' || typeof description !== 'string') return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str> parameter values are required." };
    if (typeof date === 'string' && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD" };
    if (isNaN(recordId)) return { errMsg: "recordId parameter value as a number required." };

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

        if (result?.affectedRows > 0) {
            return { succMsg: 'User record deleted successfully.' }
        }

        return { errMsg: "Something went wrong while deleting todolist record from the database. Please try again later." };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
    
}

// error message
export async function processErrStr(res, errMsg) {
    // param type check
    if (!res || (typeof errMsg !== "string")) return res.status(400).json({ errMsg: 'To process error messages response object as res parameter value and type string is required as errMsg parameter value.' });

    // default status code
    let statusCode = 500;

    // change if errMsg includes any of the specified string
    if (errMsg.includes('required') || errMsg.includes('Invalid')) {
        statusCode = 400;
    }
    else if (errMsg.includes('already exists') || errMsg.includes('does not match') || errMsg.includes('does not exist') || errMsg.includes('log out first') || errMsg.includes('already logged in') || errMsg.includes('already logged out')) {
        statusCode = 409;
    }

    // return the err massege with proper status code through response object
    return res.status(statusCode).json({ errMsg });
}