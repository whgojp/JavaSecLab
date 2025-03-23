/**
 * @description 抽取各页面中公共部分
 * @author:  whgojp
 * @email:  whgojp@foxmail.com
 * @Date: 2024/5/19 20:44
 */

layui.define(['form','table'], function (exports) { //提示：模块也可以依赖其它模块，如：layui.define('layer', callback);

    let form = layui.form;
    let table = layui.table;

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
                var value = data.field.payload;

                // 定义白名单正则表达式
                var whitelistRegex = /^[a-zA-Z0-9_\s]+$/;

                // 检查输入值是否符合白名单要求
                if (layFilter==="safe1-CheckUserInput-front" && !whitelistRegex.test(value)) {
                    layer.msg('输入内容包含非法字符，请检查输入', {icon: 2, offset: '10px'});
                    return false; // 取消表单提交
                } else {
                    data.field.type = type; // 添加类型字段
                    if (reqType === 'post') {
                        submitPostReq(data.field, path, resultId);
                    } else {
                        submitGetReq(data.field, path, resultId);
                    }
                    return false; // 取消表单提交
                }
            });
        },
        selectListenFun: function (layFilter, resultId) {
            form.on(`select(${layFilter})`, function (data) {
                console.log(data)
                $("#" + resultId).val(data.value)
            })
        },

        // table同一监听
        tableListenFun: function (layFilter,path,reqType){
            table.on(`tool(${layFilter})`, function(obj) {
                var data = obj.data;
                if (obj.event === 'delete') {
                    layer.confirm('确认删除该条记录？', function(index) {
                        $.ajax({
                            url: `${path}`,
                            type: `${reqType}`,
                            data: { id: data.id },
                            success: function(res) {
                                if (res.code === 0) {
                                    obj.del();
                                    layer.msg('删除成功', {icon: 1, offset: '10px'});
                                } else {
                                    layer.msg('删除失败', {icon: 2, offset: '10px'});
                                }
                            },
                            error: function(xhr, status, error) {
                                console.error('删除请求失败:', error);
                                layer.msg('删除请求失败，请稍后重试', {icon: 2, offset: '10px'});
                            }
                        });
                        layer.close(index);
                    });
                }
            });
        }


    };

    //输出test接口
    exports('common', obj);	//定义变量名来接收obj变量
});

