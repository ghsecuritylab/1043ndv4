(function(a){a.su.Widget("page",{defaults:{_title:"",help:"...",showTitle:false},create:function(d,b){var c=this;c.each(function(f,h){var e=a(h);a.extend(h,d,b);e.find("h2.func-title").remove();var g="";if(h.showTitle){g+='<h2 class="func-title">';g+="<span>"+h._title+"</span>";g+="</h2>"}if(h.help!=null){g+='<div class="help-container">';g+='<div class="btn-help-container">';g+='<a class="btn-help closed" name="'+h.help+'" href="javascript:void(0);"></a>';g+="</div>";g+='<div class="help-content-container">';g+='<iframe src="" id="helpFrame" style="overflow:hidden;" height="100%" width="100%" frameBorder="0" scrolling="no" marginHeight="0"  marginWidth="0" ></iframe>';g+="</div>";g+="</div>"}e.prepend(a(g)).addClass("container")});c.delegate("div.btn-help-container a.btn-help","mousedown",function(g){var f=a(this);f.addClass("clicked")}).delegate("div.btn-help-container a.btn-help","click",function(j){j.preventDefault();var g=a.su.help.width;var i=a(this),f=i.closest("div.btn-help-container");if(i.hasClass("closed")){a("div.help-content-container").css("display","block");i.closest("div.help-container").animate({width:"+="+g+"px"},200);var h=f.css("right");h=h.slice(0,h.length-2);f.animate({right:Math.abs(h)+g-i.width()},200,function(k){i.removeClass("closed")})}else{a("div.help-content-container").css("display","none");i.closest("div.help-container").animate({width:"-=0"},200);var h=f.css("right");h=h.slice(0,h.length-2);f.animate({right:Math.abs(h)-g+i.width()},200,function(){i.addClass("closed")})}})},close:function(d){var d=d||this,c=a("div.btn-help-container a.btn-help"),b=c.hasClass("closed")?false:true;if(b){c.trigger("click")}},temporaryShow:function(e,d){var e=e||this,b=a.su.help.width,c=a("div.btn-help-container a.btn-help").hasClass("closed")?true:false;operationObj=d[1];if(c){a("div.help-container").css({width:b+"px",visibility:"hidden",right:"20px"});a("div.help-content-container").css({display:"block"})}if(a.type(operationObj.operation)==="function"){operationObj.operation.call(operationObj.context)}if(c){a("div.help-container").css({width:"0px",visibility:"visible",right:"20px"});a("help-content-container").css({display:"none"})}}})})(jQuery);