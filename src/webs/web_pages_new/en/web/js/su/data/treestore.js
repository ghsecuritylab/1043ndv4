(function(a){a.su.TreeStore=function(c){var e={proxy:null,fields:[{name:"name"},{name:"path"},{name:"hasBranch"},{name:"branches"},{name:"leavesInfo"},{name:"leaves"}],keyProperty:"path"};var d=a.extend({},e,c);var b=new a.su.Store(d);b.getNode=function(g){var f=this;if(!f.map||!f.map[g]){return undefined}else{return f.map[g]}};b.loadNode=function(k,h,f){var g=this,i=b.getNode(k).path,j=a.extend({operation:"read",path:i},h);g.proxy.read(j,function(m,l,n){if(f){f.call(g,m,l,n)}g.map[k].branches=m;a(g).trigger("ev_loadnode",[g,k,m])})};b.updateMap=function(){var g=this,f=g.data[0];if(!f){return}var i={};i[f[g.keyProperty]]=f;var h=function(l){if(l.branches){for(var k=0,j=l.branches.length;k<j;k++){var m=l.branches[k];b.mapId++;i[m[g.keyProperty]]=m;h(m)}}};h(f);b.map=i};a(b).on("ev_datachanged",b.updateMap);return b}})(jQuery);