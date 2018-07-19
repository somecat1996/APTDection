/**
 * Created by lenovo on 2018/7/18.
 */
$("#results-display").ready(function() {
    $.getJSON ("/report/innerIP.json", function (data) {
        // $.each(data, function (i, item) {
        //     $.getJSON(item, function (data) {
        setTimeout(function() {
        $.each(data, function (i, item) {
            var UA = item.UA;
            var UATable = "";
            for(var i=0;i<UA.length;i++){
                var info = UA[i].info;
                UATable = UATable + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">名称</h6><p class=\"text-center\">" + UA[i].name +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">备注</h6><p class=\"text-center\">" + info.comment + "</p></div></div>" +
                    "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">描述</h6><p class=\"text-center\">" + info.desc +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">链接</h6><p class=\"text-center\">" + info.link + "</p></div></div>" +
                    "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">第一次活动时间</h6><p class=\"text-center\">" + UA[i].stime + "</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">最后一次活动时间</h6><p class=\"text-center\">" + UA[i].etime + "</p></div></div>";
                if(UA[i].type===1){
                    UATable = UATable + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\"><span class=\"label label-danger\">恶意</span></p></div><div class=\"col-md-6\"><h6 class=\"text-center\">种类</h6><p class=\"text-center\">" + info.type + "</p></div></div>";
                }else if(UA[i].type===0){
                    UATable = UATable + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\"><span class=\"label label-success\">良性</span></p></div><div class=\"col-md-6\"><h6 class=\"text-center\">种类</h6><p class=\"text-center\">" + info.type + "</p></div></div>";
                }
                if(i<UA.length-1){
                    UATable = UATable + "<hr>";
                }
            }
            UATable = "<p data-toggle=\"modal\" data-target=\"." + item.IP.replace(/\./g,"_") + "\">详细信息</p>" +
                "<div class=\"modal fade " + item.IP.replace(/\./g,"_") + "\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"gridSystemModalLabel\" aria-hidden=\"true\" style=\"display: none;\">" +
                "<div class=\"modal-dialog modal-lg\">" +
                "<div class=\"modal-content\">" +
                "<div class=\"modal-header\">" +
                "<button type=\"button\" class=\"close\" data-dismiss=\"modal\" aria-hidden=\"true\">×</button>" +
                "<h5 class=\"modal-title\" id=\"myLargeModalLabel\">详细信息</h5>" +
                "</div><div class=\"modal-body\">" +
                UATable + "</div><div class=\"modal-footer\">" +
                "<button type=\"button\" class=\"btn btn-danger text-left\" data-dismiss=\"modal\">Close</button>" +
                "</div></div></div></div>";
            UATable = "<tr><td>" + item.IP +
                "</td><td>" + item.total +
                "</td><td>" + item.malicious +
                "</td><td>" + UATable + "</td></tr>";
            $("#results-display").append(UATable);
        });
        }, 1);
    });
    //     });
    // });
});
// setTimeout(function() {
//   $('#datable_1').DataTable();
// }, 100 * 1000);
// window.onload = function() {$('#datable_1').DataTable();}
$(document).ready(function() {
    $('#datable_1').DataTable();
});