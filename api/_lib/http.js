function sendJson(res, statusCode, data) {
  return res.status(statusCode).json(data);
}

function allowMethods(req, res, methods) {
  if (!methods.includes(req.method)) {
    sendJson(res, 405, {
      ok: false,
      message: "Method not allowed"
    });
    return false;
  }

  return true;
}

module.exports = {
  sendJson,
  allowMethods
};
