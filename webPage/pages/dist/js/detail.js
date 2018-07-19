/**
 * Created by lenovo on 2018/7/19.
 */
$.getJSON ("/report/Background_PC/index.json", function (data) {
    $.each(data, function (i, item) {
        $.getJSON(item, function (data) {
            $.each(data, function (i, item) {
                var info = item.info;
                var type = '';
                if(item.type==="1"){
                    type = "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\"><span class=\"label label-danger\">恶意</span></p></div><div class=\"col-md-6\"><h6 class=\"text-center\">种类</h6><p class=\"text-center\">" + info.type + "</p></div></div>";
                }else{
                    type = "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\"><span class=\"label label-success\">良性</span></p></div><div class=\"col-md-6\"><h6 class=\"text-center\">种类</h6><p class=\"text-center\">" + info.type + "</p></div></div>";
                }
                $("#results-display").append("<tr><td>" + item.srcIP +
                    "</td><td>" + item.srcPort +
                    "</td><td>" + item.dstIP +
                    "</td><td>" + item.dstPort +
                    "</td><td>" + item.time +
                    "</td><td>" + type +
                    "</td><td>" + item.UA +
                    "</td><td>" + info.comment +
                    "</td><td>" + info.desc +
                    "</td><td>" + info.link +
                    "</td><td>" + info.type + "</td></tr>");
            });
        });
    });
});
window.onload = function() {$('#footable_3').footable();}