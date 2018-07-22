/**
 * Created by lenovo on 2018/7/20.
 */
var count = 0;
var S = 0;
var flag = 1;
$("#results-display").ready(function() {
    // $.getJSON ("testFiles/ua_detail.json", function (data) {
    $.getJSON ("/report/UA.json", function (data) {
        S = data.length;
        // $.each(data, function (i, item) {
        //     $.getJSON(item, function (data) {
        $.each(data, function (i, item) {
            count++;
            var info = item.info;
            var Table = "<div class=\"row\"><div class=\"col-md-12\"><h5 class='text-center'>User Agent信息</h5></div></div>"
            Table = Table + "<hr><div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\">" + info.type + "</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">备注</h6><p class=\"text-center\">" + info.comment + "</p></div></div>" +
                "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">描述</h6><p class=\"text-center\">" + info.desc + "</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">链接</h6><p class=\"text-center\">" + info.link + "</p></div></div>";
            Table = Table + "<div class=\"row\"><div class=\"col-md-12\"><h5 class='text-center'>通信详细信息</h5></div></div>"
            var connection = ''
            for(let i=0;i<item.connection.length;i++){
                connection = connection + "<hr>"
                connection = connection + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">本地主机</h6><p class=\"text-center\">" + item.connection[i].src + "</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">恶意服务器</h6><p class=\"text-center\">" + item.connection[i].dst + "</p></div></div>";
                connection = connection + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">首次活动时间</h6><p class=\"text-center\">" + item.connection[i].stime + "</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">最后活动时间</h6><p class=\"text-center\">" + item.connection[i].etime + "</p></div></div>";
            }
            Table = Table + connection;
            Table = "<p data-toggle=\"modal\" data-target=\".modal" + count.toString() + "\">详细信息</p>" +
                "<div class=\"modal fade modal" + count.toString() + "\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"gridSystemModalLabel\" aria-hidden=\"true\" style=\"display: none;\">" +
                "<div class=\"modal-dialog modal-lg\">" +
                "<div class=\"modal-content\">" +
                "<div class=\"modal-header\">" +
                "<button type=\"button\" class=\"close\" data-dismiss=\"modal\" aria-hidden=\"true\">×</button>" +
                "<h5 class=\"modal-title\" id=\"myLargeModalLabel\">详细信息</h5>" +
                "</div><div class=\"modal-body\">" +
                Table + "</div><div class=\"modal-footer\">" +
                "<button type=\"button\" class=\"btn btn-danger text-left\" data-dismiss=\"modal\">Close</button>" +
                "</div></div></div></div>";
            var type;
            if(item.type===1){
                type = "<span class=\"label label-danger\">恶意</span>";
            }else{
                type = "<span class=\"label label-success\">良性</span>";
            }
            Table = "<tr><td>" + item.name +
                "</td><td>" + type +
                "</td><td>" + item.stime +
                "</td><td>" + item.etime +
                "</td><td>" + Table + "</td></tr>";
            $("#results-display").append(Table);
            if(S===count){flag=0;}
        });
    });
    //     });
    // });
});
window.onload = function() {
    while(flag===1){}
    $('#datable_1').DataTable();
}