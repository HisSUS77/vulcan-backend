# helpers.js - vulnerable JS patterns
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const child_process = require('child_process');

function cmd(userInput) {
  child_process.exec('ls ' + userInput);
}

function xss(req, res) {
  res.send('<div>' + req.query.name + '</div>');
}

function ssrf(url) {
  const axios = require('axios');
  return axios.get(url);
}

function protoPollution(data) {
  Object.assign({}, data);
}

function weakCrypto(data) {
  crypto.createHash('md5').update(data).digest('hex');
}

function pathTraversal(p) {
  fs.readFile(p, 'utf8', () => {});
}

function insecureRandom() {
  return Math.random();
}

function insecureCookie(res) {
  res.cookie('id', '123');
}

module.exports = { cmd, xss, ssrf, protoPollution, weakCrypto, pathTraversal, insecureRandom, insecureCookie };
