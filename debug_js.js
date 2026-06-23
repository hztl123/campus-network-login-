/**
 * debug_js.js — 打印 JS 加密的每个中间步骤
 */
const crypto = require("crypto");

// === base64 ===
const _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
const _PAD = "=";

function _encode(s) {
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
            x.push(_ALPHA.charAt(b10 >>> 18) + _ALPHA.charAt(b10 >>> 12 & 0x3F) + _PAD + _PAD);
            break;
        case 2:
            b10 = (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8);
            x.push(_ALPHA.charAt(b10 >>> 18) + _ALPHA.charAt(b10 >>> 12 & 0x3F) + _ALPHA.charAt(b10 >>> 6 & 0x3F) + _PAD);
            break;
    }
    return x.join("");
}

function md5(str, key) {
    if (key === undefined) key = "";
    return crypto.createHash("md5").update(key + str).digest("hex");
}

function sha1(str) {
    return crypto.createHash("sha1").update(str).digest("hex");
}

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
    for (var i = 0; i < d; i++) {
        a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
    }
    return a.join('');
}

function xxtea(str, key) {
    var v = s_func(str, true);
    var k = s_func(key, false);
    if (k.length < 4) k.length = 4;
    var n = v.length - 1;
    if (n < 1) return str;
    var z = v[n], y = v[0];
    var DELTA = 0x9E3779B9;
    var MASK = 0xFFFFFFFF;
    var q = Math.floor(6 + 52 / (n + 1));
    var d = 0;
    while (0 < q--) {
        d = (d + DELTA) & MASK;
        var e = (d >>> 2) & 3;
        for (var p = 0; p < n; p++) {
            y = v[p + 1];
            var m = (z >>> 5) ^ ((y << 2) & MASK);
            m = (m + ((y >>> 3) ^ ((z << 4) & MASK))) & MASK;
            m = (m ^ (d ^ y)) & MASK;
            m = (m + (k[(p & 3) ^ e] ^ z)) & MASK;
            z = v[p] = (v[p] + m) & MASK;
        }
        y = v[0];
        m = (z >>> 5) ^ ((y << 2) & MASK);
        m = (m + ((y >>> 3) ^ ((z << 4) & MASK))) & MASK;
        m = (m ^ (d ^ y)) & MASK;
        m = (m + (k[(p & 3) ^ e] ^ z)) & MASK;
        z = v[n] = (v[n] + m) & MASK;
    }
    return l_func(v, false);
}

// === 测试 ===
const jsonStr = '{"username":"00217324@cmcc","password":"203810","ip":"10.246.6.57","acid":"8","enc_ver":"srun_bx1"}';
const token = "87f474935d616d409de16d8a8c0004b5d1e70776d54092b13fc2be5951eddbd3";

console.log("JSON:", jsonStr);
console.log("Token:", token);
console.log("");

// s() 结果
const v_arr = s_func(jsonStr, true);
const k_arr = s_func(token, false);
while (k_arr.length < 4) k_arr.push(0);
console.log("v (数据uint32数组):", v_arr.length, "个元素");
console.log("  前3个: 0x" + v_arr.slice(0,3).map(x=>(x>>>0).toString(16)).join(", 0x"));
console.log("  最后(长度标记):", v_arr[v_arr.length-1], "(0x" + (v_arr[v_arr.length-1]>>>0).toString(16) + ")");
console.log("k (密钥uint32数组, 含补0):", k_arr.length, "个元素");
console.log("  值: 0x" + k_arr.map(x=>(x>>>0).toString(16)).join(", 0x"));

// XXTEA
const xxteaResult = xxtea(jsonStr, token);
console.log("\nXXTEA结果长度:", xxteaResult.length);

// base64
const base64Result = _encode(xxteaResult);
console.log("Base64结果:", base64Result.substring(0, 60) + "...");

const finalResult = "{SRBX1}" + base64Result;
console.log("\n最终info:", finalResult.substring(0, 80) + "...");
console.log("最终info长度:", finalResult.length);

// MD5
const hmd5 = md5("203810", token);
console.log("hmd5:", hmd5);
