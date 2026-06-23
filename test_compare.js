/**
 * test_compare.js — 用学校 Portal 的加密逻辑跑一遍，跟 Python 输出对比
 *
 * 用法：node test_compare.js
 */

// 模拟学校的 base64 库（从 all.min.js 提取核心逻辑）
const _ALPHA_ORIG = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
let _ALPHA = _ALPHA_ORIG;
const _PADCHAR = "=";

function _encode(s) {
    if (arguments.length !== 1) throw "exactly one argument required";
    s = String(s);
    let i, b10, x = [], imax = s.length - s.length % 3;
    if (s.length === 0) return s;
    for (i = 0; i < imax; i += 3) {
        b10 = (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8) | s.charCodeAt(i + 2);
        x.push(_ALPHA.charAt(b10 >>> 18));
        x.push(_ALPHA.charAt(b10 >>> 12 & 0x3F));
        x.push(_ALPHA.charAt(b10 >>> 6 & 0x3F));
        x.push(_ALPHA.charAt(b10 & 0x3F));
    }
    switch (s.length - imax) {
        case 1:
            b10 = s.charCodeAt(i) << 16;
            x.push(_ALPHA.charAt(b10 >>> 18) + _ALPHA.charAt(b10 >>> 12 & 0x3F) + _PADCHAR + _PADCHAR);
            break;
        case 2:
            b10 = (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8);
            x.push(_ALPHA.charAt(b10 >>> 18) + _ALPHA.charAt(b10 >>> 12 & 0x3F) + _ALPHA.charAt(b10 >>> 6 & 0x3F) + _PADCHAR);
            break;
    }
    return x.join("");
}

function setAlpha(s) { _ALPHA = s; }

// md5 和 sha1（用 Node.js 内置 crypto）
const crypto = require("crypto");
function md5(str, key) {
    if (key === undefined) key = "";
    return crypto.createHash("md5").update(key + str).digest("hex");
}
function sha1(str) {
    return crypto.createHash("sha1").update(str).digest("hex");
}

// ===== 复制 Portal.js 的 s/l/encode 函数 =====
function s_func(a, b) {
    var c = a.length;
    var v = [];
    for (var i = 0; i < c; i += 4) {
        v[i >> 2] = a.charCodeAt(i) | (a.charCodeAt(i + 1) || 0) << 8 | (a.charCodeAt(i + 2) || 0) << 16 | (a.charCodeAt(i + 3) || 0) << 24;
    }
    if (b) v[v.length] = c;
    return v;
}

function l_func(a, b) {
    var d = a.length;
    var c = (d - 1) << 2;
    if (b) {
        var m = a[d - 1];
        if (m < c - 3 || m > c) return null;
        c = m;
    }
    for (var i = 0; i < d; i++) {
        a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
    }
    return b ? a.join('').substring(0, c) : a.join('');
}

function encode_func(str, key) {
    if (str === '') return '';
    var v = s_func(str, true);
    var k = s_func(key, false);
    if (k.length < 4) k.length = 4;
    var n = v.length - 1,
        z = v[n],
        y = v[0],
        c = 0x86014019 | 0x183639A0,
        m, e, p,
        q = Math.floor(6 + 52 / (n + 1)),
        d = 0;
    while (0 < q--) {
        d = (d + c) & 0xFFFFFFFF;
        e = (d >>> 2) & 3;
        for (p = 0; p < n; p++) {
            y = v[p + 1];
            m = (z >>> 5) ^ ((y << 2) & 0xFFFFFFFF);
            m = (m + ((y >>> 3) ^ ((z << 4) & 0xFFFFFFFF))) & 0xFFFFFFFF;
            m = (m ^ (d ^ y)) & 0xFFFFFFFF;
            m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF;
            z = v[p] = (v[p] + m) & 0xFFFFFFFF;
        }
        y = v[0];
        m = (z >>> 5) ^ ((y << 2) & 0xFFFFFFFF);
        m = (m + ((y >>> 3) ^ ((z << 4) & 0xFFFFFFFF))) & 0xFFFFFFFF;
        m = (m ^ (d ^ y)) & 0xFFFFFFFF;
        m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF;
        z = v[n] = (v[n] + m) & 0xFFFFFFFF;
    }
    return l_func(v, false);
}

// ===== 模拟 _encodeUserInfo =====
function encodeUserInfo(info, token) {
    setAlpha("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA");
    var jsonStr = JSON.stringify(info);
    var encoded = encode_func(jsonStr, token);
    var result = _encode(encoded);  // base64.encode
    setAlpha(_ALPHA_ORIG);  // restore
    return "{SRBX1}" + result;
}

// ===== 测试 =====
const testInfo = {
    username: "00217324@cmcc",
    password: "test123",
    ip: "10.246.6.57",
    acid: "8",
    enc_ver: "srun_bx1"
};
const testToken = "test_challenge_12345";
const testPassword = "test123";

const encryptedInfo = encodeUserInfo(testInfo, testToken);
const hmd5 = md5(testPassword, testToken);

console.log("=== JS 加密结果 ===");
console.log("encrypted_info:", encryptedInfo);
console.log("encrypted_info 长度:", encryptedInfo.length);
console.log("hmd5 (MD5):", hmd5);
console.log("");

// 计算 chksum
const parts = [
    testToken, testInfo.username,
    testToken, hmd5,
    testToken, testInfo.acid,
    testToken, testInfo.ip,
    testToken, "200",
    testToken, "1",
    testToken, encryptedInfo,
];
const chksum = sha1(parts.join(""));
console.log("chksum:", chksum);
