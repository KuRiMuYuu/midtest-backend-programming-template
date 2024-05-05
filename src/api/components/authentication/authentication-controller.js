const { errorResponder, errorTypes } = require('../../../core/errors');
const authenticationServices = require('./authentication-service');

// Object to store failed login attempts and timestamps
const failedLoginAttempts = {};

/**
 * Handle login request
 * @param {object} request - Express request object
 * @param {object} response - Express response object
 * @param {object} next - Express route middlewares
 * @returns {object} Response object or pass an error to the next route
 */
async function login(request, response, next) {
  const { email, password } = request.body;

  try {
    // Check if the email has reached the login attempt limit
    if (failedLoginAttempts[email] && failedLoginAttempts[email].attemptCount >= 5) {
      const timeDiff = new Date() - failedLoginAttempts[email].timestamp;
      if (timeDiff < 30 * 60 * 1000) {
        // If within 30 minutes and limit exceeded, return 403 Forbidden
        throw errorResponder(
          errorTypes.INVALID_CREDENTIALS,
          'Too many failed login attempts.',
          403,
          {
            timestamp: failedLoginAttempts[email].timestamp.toISOString(),
            attemptCount: failedLoginAttempts[email].attemptCount
          }
        );
      } else {
        // If past 30 minutes, reset the attempt count
        failedLoginAttempts[email].attemptCount = 0;
      }
    }

    // Check login credentials
    const loginSuccess = await authenticationServices.checkLoginCredentials(
      email,
      password
    );

    if (!loginSuccess) {
      // If login failed, update the attempt count
      if (!failedLoginAttempts[email]) {
        failedLoginAttempts[email] = { attemptCount: 1, timestamp: new Date() };
      } else {
        failedLoginAttempts[email].attemptCount++;
        failedLoginAttempts[email].timestamp = new Date();
      }

      throw errorResponder(
        errorTypes.INVALID_CREDENTIALS,
        'Wrong email or password.',
        403,
        {
          timestamp: failedLoginAttempts[email].timestamp.toISOString(),
          attemptCount: failedLoginAttempts[email].attemptCount
        }
      );
    }

    // If login successful, reset the attempt count
    if (failedLoginAttempts[email]) {
      failedLoginAttempts[email].attemptCount = 0;
    }

    return response.status(200).json(loginSuccess);
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  login,
};
