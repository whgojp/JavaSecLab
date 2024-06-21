/**
 * @description 抽取各页面中公共部分
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/5/19 20:44
 */

layui.define(['form'], function (exports) { //提示：模块也可以依赖其它模块，如：layui.define('layer', callback);

    let form = layui.form;

    function isValidJSON(text) {
        try {
            JSON.parse(text);
            return true;
        } catch (error) {
            return false;
        }
    }

    function submitGetReq(data, path, resultId) {
        getAjaxRequst(path, data, function (res) {
            if (res) {
                console.log("后端返回：" + JSON.stringify(res));
                if (isValidJSON(JSON.stringify(res))) {
                    $("#" + resultId).html(JSON.parse(JSON.stringify(res)).msg);
                } else $("#" + resultId).html(res);

            } else {
                console.log("返回数据不存在或者请求数据失败");
            }
        });
    };

    function submitPostReq(data, path, resultId) {
        postAjaxRequst(path, data, function (res) {
            if (res) {
                console.log("后端返回：" + JSON.stringify(res));
                if (isValidJSON(JSON.stringify(res))) {
                    $("#" + resultId).html(JSON.parse(JSON.stringify(res)).msg);
                } else $("#" + resultId).html(res);

            } else {
                console.log("返回数据不存在或者请求数据失败");
            }
        });
    };
    base = "http://localhost:8080";


    let obj = {
        submitGetReq,
        submitPostReq,
        formListenFun: function (layFilter, type, path, resultId, reqType) {
            form.on(`submit(${layFilter})`, function (data) {
                data.field.type = type;
                if (reqType === 'post') {
                    submitPostReq(data.field, path, resultId)
                } else submitGetReq(data.field, path, resultId);
                return false;
            });
        },
        selectListenFun: function (layFilter, resultId) {
            form.on(`select(${layFilter})`, function (data) {
                console.log(data)
                $("#" + resultId).val(data.value)
            })
        },
        //设置token
        setToken: function (value) {
            return layui.data('token', {
                key: 'token',
                value: value,
            });
        },

        //获取token
        getToken: function () {
            return layui.data('token').token;
        },


        // codeMirror复用

    };

    //输出test接口
    exports('common', obj);	//定义变量名来接收obj变量
});

