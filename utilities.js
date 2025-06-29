import pool from "./database.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
dotenv.config();

// Set the domain and secure cookie based on the environment
// If in production, use the domain from environment variables; otherwise, use localhost
const DomainForCookie = process.env.NODE_ENV === 'production' ? process.env.SITE_DOMAIN : 'localhost';
const SecureCookie = process.env.NODE_ENV === 'production' ? true : false;

// capitalize the first letter of a string
function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// capitalize the first letter of each word in a string
function capitalizeWords(str) {
    return str
        .split(' ')
        .map(word => capitalize(word))
        .join(' ');
}

// hash password function
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(11);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
}

// check password function
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

// check if time has passed or not
function hasDateTimePassed(dateStr, timeStr) {
    // Parse the time into 24-hour format
    const [time, modifier] = timeStr.split(' ');
    let [hours, minutes] = time.split(':').map(Number);

    if (modifier === 'PM' && hours !== 12) {
        hours += 12;
    } else if (modifier === 'AM' && hours === 12) {
        hours = 0;
    }

    // Create the target Date object
    const targetDateTime = new Date(dateStr);
    targetDateTime.setHours(hours, minutes, 0, 0); // set hours, minutes, seconds, milliseconds

    // Get current Date and time
    const now = new Date();

    // Compare
    return targetDateTime < now;
}

// check if the date is today or not
function isNotPastDate(inputDateStr) {
    // Parse the input string into a Date object
    const [year, month, day] = inputDateStr.split('/').map(Number);
    const inputDate = new Date(year, month - 1, day); // JS months are 0-based

    // Get today's date at midnight (00:00:00)
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Strip time

    // Compare
    return inputDate >= today;
}

// add 5 minutes to the current time
function addMinutesToCurrentTime(minutesToAdd) {
    const date = new Date(); // current date and time
    date.setMinutes(date.getMinutes() + minutesToAdd);

    // Format to 12-hour time with AM/PM
    let hours = date.getHours();
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';

    hours = hours % 12;
    if (hours === 0) hours = 12;

    return `${hours}:${minutes} ${ampm}`;
}

// sort todo objects by time
function sortTimeObjects(arr) {
    return arr.sort((a, b) => {
        const toMinutes = timeStr => {
            const [time, modifier] = timeStr.split(" ");
            let [hours, minutes] = time.split(":").map(Number);

            if (modifier === "PM" && hours !== 12) hours += 12;
            if (modifier === "AM" && hours === 12) hours = 0;

            return hours * 60 + minutes;
        };

        return toMinutes(a.Time) - toMinutes(b.Time);
    });
}

// sort time array of strings
function sortTimes(times) {
    return times.sort((a, b) => {
        const to24Hour = timeStr => {
            const [time, modifier] = timeStr.split(" ");
            let [hours, minutes] = time.split(":").map(Number);

            if (modifier === "PM" && hours !== 12) hours += 12;
            if (modifier === "AM" && hours === 12) hours = 0;

            return hours * 60 + minutes; // total minutes since midnight
        };

        return to24Hour(a) - to24Hour(b);
    });
}

// login and register
export async function register(userName, userEmail, userPassword) {
    // safeguard cheking all the parameters
    if (!userName || !userEmail || !userPassword) {
        return { errMsg: "The parameter values for each userName, userEmail, userPassword are required to insert the user record to the database for registration." };
    }

    // check if user record existed in users table
    try {
        const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT NOT NULL AUTO_INCREMENT,
                    user_name VARCHAR(256) NOT NULL,
                    user_email VARCHAR(256) NOT NULL,
                    hashed_pass VARCHAR(256) NOT NULL,
                    refresh_token VARCHAR(256) DEFAULT NULL,
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
            const token = jwt.sign({ email: userEmail }, process.env.APP_SECRET, { expiresIn: '5m' });
            const verificationLink = `${process.env.SITE_URL}/verify-email/${token}`;

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                port: 465,
                secure: true,
                auth: {
                    user: process.env.APP_EMAIL,
                    pass: process.env.APP_PASS,
                },
            });

            await transporter.sendMail({
                from: process.env.APP_EMAIL,
                to: userEmail,
                subject: "Verify Your Email For Todo List App",
                html: `
                    <html>
                        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                            <h2>Verify Your Email. Valid until ${addMinutesToCurrentTime(5)}</h2>
                            <p>Hello ${userName}, <br> Thank you for signing up for the Todo List App!</p>
                            <p>Please click the link below to verify your email address:</p>
                            <p><a href="${verificationLink}" style="color: #1a73e8;">Verify Email</a></p>
                            <p>If you did not sign up for this account, you can ignore this email.</p>
                            <hr>
                            <p style="font-size: 0.9em;">You are receiving this email because you signed up for the Todo List App.</p>
                        </body>
                    </html>
                `
            });

            return { succMsg: `User Registration Successfull. An verification email has sent to user and User Record has been added to database successfully.` };
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
    // safeguard cheking all the parameters
    if (!token) {
        return { errMsg: "The parameter value for each token is required to verify the user email." };
    }

    try {
        // decode the given token and get the email from it
        const decoded = jwt.verify(token, process.env.APP_SECRET);
        const email = decoded.email;

        // update sql database column email_varified and mark the user as verified
        const [result] = await pool.query(`UPDATE users SET email_varified = 1 WHERE user_email = ? AND email_varified = ?`, [email, 0]);

        // if no rows were affected, it means the user was not found or already verified
        if (result.affectedRows === 0) {
            return { errMsg: "No user found with that email with unverified status." };
        }

        return { succMsg: 'Email verified successfully!' };
    } catch (err) {
        console.error("Invalid or expired token", err.message);
        return { errMsg: err.message };
    }
}

// forgot password
export async function forgotPassword(userEmail) {
    // safeguard cheking all the parameters
    if (!userEmail) {
        return { errMsg: "The parameter value for each userEmail is required to send the forgot password link to user email." };
    }

    try {
        // get the user data from users table by user_email or if login log_in_Status is 1 then return the message user already logged in
        const [doesUserExist] = await pool.query(`SELECT * FROM users WHERE user_email = ?`, [userEmail]);

        if (doesUserExist.length === 0 || doesUserExist[0].email_varified === 0) {
            return { errMsg: doesUserExist.length === 0 ? "User record does not exist in the database." : "User Email is not verified yet." };
        } else if (doesUserExist[0].log_in_Status === 1) {
            return { errMsg: 'You can not update the password while you are still logged in. Please log out first to update password.' };
        }

        // send the verification email to the user email address and return the success message
        const token = jwt.sign({ email: userEmail }, process.env.APP_SECRET, { expiresIn: '5m' });
        const verificationLink = `${process.env.SITE_URL}/update-password/${token}`;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            port: 465,
            secure: true,
            auth: {
                user: process.env.APP_EMAIL,
                pass: process.env.APP_PASS,
            },
        });

        await transporter.sendMail({
            from: process.env.APP_EMAIL,
            to: userEmail,
            subject: "Update Your Password For Todo List App",
            html: `
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                        <p>Hello ${doesUserExist[0].user_name}, <br> Thank you for signing up for the Todo List App!</p>
                        <h2>Update Your Passowrd. Valid until ${addMinutesToCurrentTime(5)}</h2>
                        <p>Please click the link below to update your todolist app password:</p>
                        <p><a href="${verificationLink}" style="color: #1a73e8;">Update Passowrd</a></p>
                        <p>If you did not intend for updating passowrd of todolist app, you can ignore this email.</p>
                        <hr>
                        <p style="font-size: 0.9em;">You are receiving this email because you intended to update passowrd of Todo List App.</p>
                    </body>
                </html>
            `
        });

        return { succMsg: `Password reset link has been sent to your email address.` };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// update password
export async function updatePassword(token, newPassword) {
    // safeguard cheking all the parameters
    if (!token || !newPassword) {
        return { errMsg: "The parameter values for each token and newPassword are required to update password." };
    }

    try {
        const decoded = jwt.verify(token, process.env.APP_SECRET);
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
export async function login(userEmail, userPassword, res) {
    // safeguard cheking all the parameters
    if (!userEmail || !userPassword) {
        return { errMsg: "The parameter values for each userName, userEmail, userPassword, recoveryStr are required for user login." };
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

        const payload = {
            userId: doesUserExist[0].id,
            userName: doesUserExist[0].user_name,
            userEmail: userEmail,
        };

        if (passwordMatched) {
            const secret = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
            await pool.query(`UPDATE users SET log_in_Status = ?, refresh_token = ? WHERE id = ?`, [1, refreshToken, doesUserExist[0].id]);

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                sameSite: 'Lax',
                secure: SecureCookie,
                domain: DomainForCookie,
                path: '/api',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            return { userData: { userId: doesUserExist[0].id, userEmail: userEmail, userName: doesUserExist[0].user_name, accessToken: secret } };
        } else {
            return { errMsg: 'User password does not match. Please make sure you are providing the user email and password correctly first.' };
        }
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// refresh token
export async function generateAccessToken(res, token) {
    if (!res || !token) {
        console.log("here");
        return { errMsg: `${!res ? "Response Object is required to generate new access token." : "Invalid Refresh Token."}` };
    }

    try {
        const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);

        // Optional DB check (recommended)
        const [users] = await pool.query("SELECT * FROM users WHERE id = ?", [payload.userId]);

        if (!users.length || users[0].refresh_token !== token) {
            return { errMsg: !users.length ? "User not found." : "Invalid Refresh Token." };
        }

        const newAccessToken = jwt.sign(
            { userId: users[0].id, userName: users[0].user_name, userEmail: users[0].user_email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );

        return { accessToken: newAccessToken };
    } catch (err) {
        res.clearCookie('refreshToken', {
            httpOnly: true,
            sameSite: 'Lax',
            secure: SecureCookie,
            domain: DomainForCookie,
            path: '/api'
        });
        return { errMsg: "Invalid Refresh Token." };
    }
}

// logout
export async function logout(userEmail, req, res) {
    if (!userEmail || !req) {
        return { errMsg: `${!userEmail ? "User Email" : !res ? "Response Object" : "Request Object" } is required to log out the user.` };
    }

    try {
        // check if the user is logged in or not by checking the log_in_Status field in the database
        const [doesUserExist] = await pool.query(`SELECT log_in_Status, refresh_token FROM users WHERE user_email = ?`, [userEmail]);
        
        // if user not found or logged out already then retrun the error message
        if (doesUserExist.length === 0) {
            return { errMsg: "The user you are trying to log out does not exist in the database." };
        } else if (doesUserExist[0].log_in_Status === 0 || doesUserExist[0].refresh_token !== req.cookies.refreshToken) {
            return { errMsg: `${doesUserExist[0].log_in_Status === 0 ? "The user you are trying to log out is already logged out from the account." : "Invalid Refresh Token." }` };
        }

        // now update the login status to the database.
        const [updateResult] = await pool.query(`UPDATE users SET refresh_token = ?, log_in_Status = ? WHERE user_email = ?`, [null, 0, userEmail]);

        // if successfully updated the logged out field in the database then return the success message else the error message.
        if (updateResult?.affectedRows > 0 && updateResult?.changedRows > 0) {
            res.clearCookie('refreshToken', {
                httpOnly: true,
                sameSite: 'Lax',
                secure: SecureCookie,
                domain: DomainForCookie,
                path: '/api'
            });
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
export async function getTodoListData(userId, date) {
    // check the first parameter as a number available or not if not return error message
    // otherwise return an error message

    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required for getting the todo list records for the user." };
    if (!date || typeof date !== 'string' || !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD to get todo list records." };

    try {
        // try to fetch user requested data via user credentials
        const [rows] = await pool.query(`SELECT todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title' FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND todo_list_user_data.todo_date = ? AND users.log_in_Status = ?`, [userId, date, 1]);

        // if no rows are returned then return the error message
        if (rows.length === 0) {
            return { errMsg: "No record is found that get matched with your credentials in the database." };
        }
        
        // loop through the rows array
        // if the current object title is the same as the previous object title then add number property to the current object and if the number property is already present then increase the number by 1
        for(let i = 0; i < rows.length; i++) {
            if (!rows[i].Number) {
                rows[i].Number = 1;
            }
            for (let j = i + 1; j < rows.length; j++) {
                if ((rows[i].Date === rows[j].Date) && (rows[i].Title === rows[j].Title)) {
                    // if the title is the same then increase the number of todos
                    rows[i].Number = rows[i].Number + 1;

                    // remove the duplicate row
                    rows.splice(j, 1);

                    // adjust index after removal
                    j--;
                }
            }
        }

        return { cardDataArr: rows };
    }
    catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get all todo dates for a user
export async function getAllTodoDates(userId) {
    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required for getting the todo list records for the user." };

    try {
        const [rows] = await pool.query(`SELECT DISTINCT todo_list_user_data.todo_date as 'Date' FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND users.log_in_Status = ? ORDER BY todo_list_user_data.todo_date DESC`, [userId, 1]);
        
        if (rows.length === 0) {
            return { dateArr: [] };
        }

        const dateArray = rows.map(row => row.Date);
        return { dateArr: dateArray };
    }
    catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo list record for a user filtered by params
export async function getFilteredTodoList(userId, date = "", title = "") {
    // check the first parameter as a number available or not if not return error message
    if (isNaN(userId)) return { errMsg: "User Id parameter value as a number required to get filtered todolist records." };

    // check date or title parameter value is available as string and if date is available does it meet the regex format /^\d{4}-\d{2}-\d{2}/ if any of the bellow condition failed then return the error message
    if ((date && typeof date !== 'string') || (title && typeof title !== 'string')) return { errMsg: `${(date ? 'date' : 'title')} parameter values is required as strings to get filtered todolist records.` };
    if (date && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD to get filtered todolist records" };

    let queryStr = `SELECT todo_list_user_data.id as 'ID', todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title', todo_description as 'Description', todo_time as 'Time', todo_status as 'Status', user_id as 'UserID'
FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND users.log_in_Status = ?`;

    // set the initial param array
    const params = [userId, 1];

    // update the query string and push values to params
    if (date) {
        queryStr += ` AND todo_list_user_data.todo_date = ?`;
        params.push(date);
    }

    if (title) {
        queryStr += ` AND todo_list_user_data.todo_title = ?`;
        params.push(title);
    }

    // try to query to the database if get the result then return the value or return an error message
    try {
        const [rows] = await pool.query(queryStr, params);
        if (rows.length === 0) {
            return { errMsg: "No todo records are found that get matched with your credentials." };
        }

        const sortedRows = sortTimeObjects(rows);
        return { dataArr: sortedRows };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// add totolist record
export async function addTodoRecord(date, title, description, time, status, userId) {
    // check all parameter values otherwise return an error message
    if (typeof date !== 'string' || typeof title !== 'string' || typeof description !== 'string') return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str> parameter values are required for adding todos to the record." };
    if (typeof date === 'string' && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD, only YYYY-MM-DD date format required as a string for adding todos to the record." };
    if (isNaN(userId)) return { errMsg: "userId parameter value as a number required for adding todos to the record." };
    if (typeof status !== 'string') return { errMsg: "status parameter value as a string required for adding todos to the record." };
    if (status !== 'completed' && status !== 'not completed') return { errMsg: "status parameter value must be either completed or not completed for adding todos to the record." };

    // capitalize the first letter of each word in the title
    const upperCasedTitle = capitalizeWords(title);

    // check if the date is not a past date
    if (hasDateTimePassed(date, time)) return { errMsg: "The record date or time that you are trying to add is in the past. Please provide a valid date." };

    // if log_in_status is 1 then add the record to todo_list_user_data table and if table is not created already create the table first
    try {
        const createTableQuery = `
                CREATE TABLE IF NOT EXISTS todo_list_user_data (
                    id INT NOT NULL AUTO_INCREMENT,
                    todo_date VARCHAR(256) NOT NULL,
                    todo_title VARCHAR(256) NOT NULL,
                    todo_description VARCHAR(256) NOT NULL,
                    todo_time VARCHAR(256) NOT NULL,
                    todo_status VARCHAR(256) NOT NULL,
                    user_id INT NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
            `;

        await pool.query(createTableQuery);

        const [doesRowExist] = await pool.query(`SELECT todo_date, todo_time, todo_title FROM todo_list_user_data WHERE todo_date = ? AND todo_title = ? AND todo_time = ? AND user_id = ?`, [date, title, time, userId]);

        if(doesRowExist.length > 0) {
            return { errMsg: "A record with the same date, time and title already exists for this user. Please choose a different date or time or title." };
        }

        const [result] = await pool.query(`INSERT INTO todo_list_user_data (todo_date, todo_title, todo_description, todo_time, todo_status, user_id) SELECT ?, ?, ?, ?, ?, id FROM users WHERE id = ? AND log_in_Status = ?`, [date, upperCasedTitle, description, time, status, userId, 1]);

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
        return { errMsg: `recordId parameter value as a number is required to get todo list record.` };
    }

    // get the record and return it or return the error message
    try {
        const [rows] = await pool.query(`SELECT * FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.id = ? AND users.log_in_Status = ?`, [recordId, 1]);

        if (rows.length === 0) {
            return { errMsg: "No record is found that get matched with your credentials in the database." };
        }

        if (!isNotPastDate(rows[0].todo_date)) {
            return { errMsg: "The date you are trying to get is in the past. Please provide a valid date." };
        }

        return { recordData: rows[0] };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo titles
export async function getTodoTitles(userId) {
    // check userId parameter is a number type. if not return a error message.
    if (isNaN(userId)) return { errMsg: "userId parameter value must be in number type to get todo titles." };

    // get the todo titles and return it or return the error message
    try {
        const [rows] = await pool.query(`SELECT DISTINCT todo_list_user_data.todo_date as 'Date', todo_list_user_data.todo_title as 'Title' FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND users.log_in_Status = ?`, [userId, 1]);

        if (rows.length === 0) {
            return { titleArr: [] };
        }

        const titleArray = rows.filter(row => isNotPastDate(row.Date)).map(row => row.Title);

        return { titleArr: titleArray };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// get todo times for todays date
export async function getTodoTimesForToday(userId) {
    // check userId parameter is a number type. if not return a error message.
    if (isNaN(userId)) return { errMsg: "userId parameter value must be in number type to get todo times." };
    const date = new Date().toISOString().split('T')[0]; // get today's date in YYYY-MM-DD format

    // get the todo times and return it or return the error message
    try {
        const [rows] = await pool.query(`SELECT DISTINCT todo_list_user_data.todo_time as 'Time' FROM todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id WHERE todo_list_user_data.user_id = ? AND todo_list_user_data.todo_date = ? AND todo_list_user_data.todo_status = ? AND users.log_in_Status = ?`, [userId, date, "not completed", 1]);

        // if no rows are returned then return an empty object
        if (rows.length === 0) {
            return { dataObj: { date: date, timesArr: [] } };
        }

        const timesArr = rows.map(row => row.Time)

        // sort times array
        const sortedTimesArr = sortTimes(timesArr);

        // create an object with time as key and value as empty string
        const dataObj = {
            date: date,
            timesArr: sortedTimesArr
        };
        
        // return the data object
        return { dataObj: dataObj };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// modify todoList record
export async function modifyTodoRecord(date, title, description, time, status, recordId) {
    // check all parameter values otherwise return an error message
    if (typeof date !== 'string' || typeof title !== 'string' || typeof description !== 'string') return { errMsg: "date<iso date str.split[0]>, title<str>, descrition<str> parameter values are required to modify todo list record." };
    if (typeof date === 'string' && !date.match(/^\d{4}-\d{2}-\d{2}/)) return { errMsg: "Date parameter value does not match the format YYYY-MM-DD to modify todo list record" };
    if (isNaN(recordId)) return { errMsg: "recordId parameter value as a number required to modify todo list record." };
    if (typeof status !== 'string') return { errMsg: "status parameter value as a string required to modify todo list record." };
    if (status !== 'completed' && status !== 'not completed') return { errMsg: "status parameter value must be either completed or not completed to modify todo list record." };

    // check if the date is not a past date
    if (hasDateTimePassed(date, time)) return { errMsg: "The record date or time that you are trying to modify is in the past. Please provide a valid date." };

    // if log_in_status is 1 then modify the current record of todo_list_user_data table by id field
    try {
        const [rows] = await pool.query(`SELECT * FROM todo_list_user_data WHERE todo_list_user_data.id = ? AND users.log_in_Status = ?`, [recordId, 1]);

        if (rows.length === 0) {
            return { errMsg: "The record you are trying to modify does not exist in the database." };
        } else if (rows[0].user_id !== recordId) {
            return { errMsg: "You are not authorized to modify this record." };
        }

        // if user does not provide any changes to the record then return the error message
        if (rows[0].todo_date === date && rows[0].todo_title === title && rows[0].todo_description === description && rows[0].todo_time === time && rows[0].todo_status === status) {
            return { errMsg: "No changes were made to the record." };
        }

        // update the record in the database
        // check if each column of the record is already updated or not, if not then update.
        let updateQuery = `UPDATE todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id`;
        const params = [];

        if (rows[0].todo_date !== date) {
            updateQuery += ` SET todo_date = ?`;
            params.push(date);
        }

        if (rows[0].todo_title !== title) {
            updateQuery += `, todo_title = ?`;
            params.push(title);
        }

        if (rows[0].todo_description !== description) {
            updateQuery += `, todo_description = ?`;
            params.push(description);
        }

        if (rows[0].todo_time !== time) {
            updateQuery += `, todo_time = ?`;
            params.push(time);
        }

        if (rows[0].todo_time !== time) {
            updateQuery += `, todo_status = ?`;
            params.push(status);
        }

        // required queries to update the record in the database
        updateQuery += ` WHERE todo_list_user_data.id = ? AND users.log_in_Status = ?`;
        params.push(recordId, 1);

        // execute the query to update the record in the database
        const [updateResult] = await pool.query(updateQuery, params);

        // check if the record is updated successfully or not and return the success message or error message
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

// complete todo list record
export async function completeTodoRecord(userId, recordId, date) {
    // check recordId parameter is a number type. if not return a error message.
    if (isNaN(userId) || isNaN(recordId)) return { errMsg: "userId and recordId parameter value must be in number type to complete todo list record." };

    // check if the recordId is a valid number and if the date is not a past date
    if (!isNotPastDate(date)) return { errMsg: "The date you are trying to add is in the past. Please provide a valid date." };

    // if log_in_status is 1 then update the requested record of todo_list_user_data table by id field
    try {
        const [result] = await pool.query(`UPDATE todo_list_user_data JOIN users ON todo_list_user_data.user_id = users.id SET todo_status = ? WHERE todo_list_user_data.id = ? AND todo_list_user_data.todo_status = ? AND users.id = ? AND users.log_in_Status = ?`, ['completed', recordId, "not completed", userId, 1]);

        if (result?.affectedRows > 0 && result?.changedRows > 0) {
            return { succMsg: 'User record completed successfully.' }
        }

        return { errMsg: "Unable to update todolist record status in the database, It can be due to you are trying to change status of your record which is already set as completed. Please try again later." };
    } catch (err) {
        console.error("Database error:", err.message);
        return { errMsg: err.message };
    }
}

// detele todolist record
export async function deleteTodoRecord(userId, recordId) {
    // check recordId patameter is a number type. if not return a error message.
    if (isNaN(recordId)) return { errMsg: "userId and recordId parameter value must be in number type to delete todo list record." };

    // check if the recordId is a valid number and if the date is not a past date
    if (!isNotPastDate(date)) return { errMsg: "The date you are trying to add is in the past. Please provide a valid date." };

    // check if the date is not a past date
    if (hasDateTimePassed(date, time)) return { errMsg: "The date or time you when you are trying to delete is in the past. Please provide a valid date." };

    // if log_in_status is 1 then delete the requested record of todo_list_user_data table by id field
    try {
        const [result] = await pool.query(`DELETE todo_list_user_data FROM todo_list_user_data JOIN users on todo_list_user_data.user_id = users.id WHERE todo_list_user_data.id = ? AND users.id = ? AND users.log_in_Status = ?`, [recordId, userId, 1]);

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
export async function processErrStr(res, errMsg, nullType) {
    // param type check
    if (!res || (typeof errMsg !== "string")) return res.status(400).json({ errMsg: 'To process error messages response object as res parameter value and type string is required as errMsg parameter value.' });

    // default status code
    let statusCode = 500;

    // change if errMsg includes any of the specified string
    if (errMsg.includes('found that get matched with your credentials')) {
        statusCode = 200;
    }
    else if (errMsg.includes('No changes')) {
        statusCode = 304;
    }
    else if (errMsg.includes('not exist') || errMsg.includes("found")) {
        statusCode = 404;
    }
    else if (errMsg.includes('required') || errMsg.includes('can only contain') || errMsg.includes('must be') || errMsg.includes('valid')) {
        statusCode = 400;
    }
    else if (errMsg.includes('Invalid') || errMsg.includes('invalid') || errMsg.includes('Unauthorized') || errMsg.includes('unauthorized') || errMsg.includes('expired') || errMsg.includes('Expired')) {
        statusCode = 401;
    }
    else if (errMsg.includes('already exists') || errMsg.includes('not match') || errMsg.includes('log out first') || errMsg.includes('already logged in') || errMsg.includes('already logged out') || errMsg.includes('trying to')) {
        statusCode = 409;
    }

    // return the err massege with proper status code through response object
    return res.status(statusCode).json({ [nullType]: null, errMsg });
}