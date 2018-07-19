/**
 * Created by lenovo on 2018/7/18.
 */
var count = 0;
var S = 0;
var items = [];
$("#results-display").ready(function() {
    // $.getJSON ("testFiles/index.json", function (data) {
    $.getJSON ("/report/UA.json", function (data) {
        S = data.length;
        // $.each(data, function (i, item) {
        //     $.getJSON(item, function (data) {
        $.each(data, function (i, item) {
            count++;
            var info = item.info;
            var Table = "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">类型</h6><p class=\"text-center\">" + info.type +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">备注</h6><p class=\"text-center\">" + info.comment + "</p></div></div>" +
                "<div class=\"row\"><div class=\"col-md-6\"><h6 class=\"text-center\">描述</h6><p class=\"text-center\">" + info.desc +	"</p></div><div class=\"col-md-6\"><h6 class=\"text-center\">链接</h6><p class=\"text-center\">" + info.link + "</p></div></div>";
            Table = Table + "<hr><div id=\"modal" + count.toString() + "\" class=\"center-block\" style=\"width:600px;height:600px;\"></div><div class=\"label-chatrs mt-15\">" +
                "<div class=\"mb-5\"><span class=\"clabels inline-block bg-blue mr-5\"></span><span class=\"clabels-text font-12 inline-block txt-dark capitalize-font\">内部IP地址</span>" +
                "</div><div class=\"mb-5\"><span class=\"clabels inline-block bg-light-blue mr-5\"></span><span class=\"clabels-text font-12 inline-block txt-dark capitalize-font\">User-Agent</span>" +
                "</div><div class=\"\"><span class=\"clabels inline-block bg-red mr-5\"></span><span class=\"clabels-text font-12 inline-block txt-dark capitalize-font\">外部IP地址</span>" +
                "</div></div>";
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
            if(item.type==="1"){
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
            items.push(item);
        });
    });
    //     });
    // });
});

function B(item, c) {
    var data = [];
    data.push({
        "name": item.name,
        "value": "",
        x: 300,
        y: 300,
        "symbolSize": 40,
        "category": "a",
        "draggable": "true",
        itemStyle: {
            normal: {
                color: ['#958FEF'],
            }
        }
    });
    var srcIP = item.srcIP;
    for(let i=0;i<srcIP.length;i++){
        data.push({
            "name": item.srcIP[i],
            "value": "",
            x: 300 + 50*Math.cos(-1.57*(i+1)/(item.srcIP.length+1)),
            y: 300 + 50*Math.sin(-1.57*(i+1)/(item.srcIP.length+1)),
            "symbol": "triangle",
            "symbolSize": 20,
            "category": "b",
            "draggable": "true",
            itemStyle: {
                normal: {
                    color: ['#635bd6'],
                }
            }
        });
    }
    for(let i=0;i<item.dstIP.length;i++){
        data.push({
            "name": item.dstIP[i],
            "value": "",
            x: 300 + 50*Math.cos(1.57*(i+1)/(item.dstIP.length+1)),
            y: 300 + 50*Math.sin(1.57*(i+1)/(item.dstIP.length+1)),
            "symbol": "rect",
            "symbolSize": 20,
            "category": "c",
            "draggable": "true",
            itemStyle: {
                normal: {
                    color: ['#F73414'],
                }
            }
        });
    }
    var links = [];
    for(let i=0;i<item.srcIP.length;i++){
        links.push(
            {
            "source": item.name,
            "target": item.srcIP[i]
        });
    }
    for(let i=0;i<item.dstIP.length;i++){
        links.push(
            {
            "source": item.name,
            "target": item.dstIP[i]
        });
    }

    var echartsConfig = function() {
        var eChart_1 = echarts.init(document.getElementById("modal" + c.toString()));
        var option = {
            tooltip: {
                backgroundColor: 'rgba(33,33,33,1)',
                borderRadius: 0,
                padding: 10,
                axisPointer: {
                    type: 'cross',
                    label: {
                        backgroundColor: 'rgba(33,33,33,1)'
                    }
                },
                textStyle: {
                    color: '#fff',
                    fontStyle: 'normal',
                    fontWeight: 'normal',
                    fontFamily: "'Montserrat', sans-serif",
                    fontSize: 12
                }
            },
            animationDuration: 3000,
            animationEasingUpdate: 'quinticInOut',
            series: [{
                name: '节点',
                type: 'graph',
                layout: 'force',
                force: {
                    //initLayout: ...,
                    repulsion: 50,
                    gravity: 0.1,
                    // edgeLength: 30,
                    layoutAnimation: true,
                },
                data: data,
                links: links,
                categories: [{
                    'name': 'a'
                }, {
                    'name': 'b'
                }, {
                    'name': 'c'
                }],
                focusNodeAdjacency: true,
                roam: true,
                label: {
                    normal: {
                        position: 'right',
                        show: true,
                    }
                },

                lineStyle: {
                    normal: {
                        show: true
                    }
                }
            }]
        };
        eChart_1.setOption(option);
        eChart_1.resize();
    };
    echartsConfig();
    /*****Resize function start*****/
    var echartResize;
    $(window).on("resize", function () {
        /*E-Chart Resize*/
        clearTimeout(echartResize);
        echartResize = setTimeout(echartsConfig, 200);
    }).resize();
    /*****Resize function end*****/
}

window.onload = function() {
    $('#datable_1').DataTable();
    while(count<S){}
    for(let i=0;i<items.length;i++){
        B(items[i], i+1);
    }
}
