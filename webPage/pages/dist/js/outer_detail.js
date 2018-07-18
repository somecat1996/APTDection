/**
 * Created by lenovo on 2018/7/18.
 */
$(document).ready(function() {
    $.getJSON ("/report/outerIP/index.json", function (data) {
        $.each(data, function (i, item) {
            $.getJSON(item, function (data) {
                $.each(data, function (i, item) {
                    var inner = item.inner;
                    var Table = "";
                    for(var i=0;i<inner.length;i++){
                        Table = Table + "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">IP地址</h6><p class=\"text-center\">" + inner[i].IP +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">首次活动时间</h6><p class=\"text-center\">" + inner[i].stime + "</p></div></div>" +
                            "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">UA名称</h6><p class=\"text-center\">" + inner[i].UA +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">最后活动时间</h6><p class=\"text-center\">" + inner[i].etime + "</p></div></div>";
                        if(i<inner.length-1){
                            Table = Table + "<hr>";
                        }
                    }
                    Table = "<p data-toggle=\"modal\" data-target=\"." + item.IP.replace(/\./g,"_") + "\">详细信息</p>" +
                        "<div class=\"modal fade " + item.IP.replace(/\./g,"_") + "\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"gridSystemModalLabel\" aria-hidden=\"true\" style=\"display: none;\">" +
                        "<div class=\"modal-dialog modal-lg\">" +
                        "<div class=\"modal-content\">" +
                        "<div class=\"modal-header\">" +
                        "<button type=\"button\" class=\"close\" data-dismiss=\"modal\" aria-hidden=\"true\">×</button>" +
                        "<h5 class=\"modal-title\" id=\"myLargeModalLabel\">内部通信IP信息</h5>" +
                        "</div><div class=\"modal-body\">" +
                        Table + "</div><div class=\"modal-footer\">" +
                        "<button type=\"button\" class=\"btn btn-danger text-left\" data-dismiss=\"modal\">Close</button>" +
                        "</div></div></div></div>";
                    var type;
                    if(item.type==="1"){
                        type = "<span class=\"label label-danger\">恶意</span>";
                    }else{
                        type = "<span class=\"label label-success\">良性</span>";
                    }
                    Table = "<tr><td>" + item.IP +
                        "</td><td>" + type +
                        "</td><td>" + item.stime +
                        "</td><td>" + item.etime +
                        "</td><td>" + Table + "</td></tr>";
                    $("#results-display").append(Table);
                });
            });
        });
    });
    $('#datable_1').DataTable();
});