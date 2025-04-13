module.exports = (req, res, next) => {
    const userId = req.headers['x-user-id'];
  
    if (userId) {
      req.user = { user_id: userId }; // 👈 то самое
    }
  
    next();
  };