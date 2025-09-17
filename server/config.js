/**
 * Configuration file for the Communication LTD Server
 */

const config = {
  // Server Configuration
  port: 5000,
  nodeEnv: 'development',
  
  passwordHistoryLimit: 3, // min 1 max 100
  passwordLength: 10,
  passwordLimitation: {
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSpecial: true,
  },
  dictionary: ['123456', '123456789', 'qwerty', 'password', '12345', '12345678',
    '111111', '123123', 'abc123', '1234567', 'password1', '1234',
    'iloveyou', '1q2w3e4r', '000000', 'qwerty123', 'zaq12wsx',
    'dragon', 'sunshine', 'princess', 'letmein', '654321', 'monkey',
    '27653', '1qaz2wsx', '121212', 'admin', 'welcome', 'login',
    'football', 'baseball', 'starwars', 'whatever', 'trustno1',
    'superman', 'hello', 'freedom', 'batman', 'master'],
  loginAttempts: 3,
};

module.exports = config;
