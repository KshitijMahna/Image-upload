jQuery.noConflict()

var ddpowerzoomer={
	dsetting: {defaultpower:2, powerrange:[2,7], magnifiersize:[175, 175]},
	mousewheelevt: (/Firefox/i.test(navigator.userAgent))? "DOMMouseScroll" : "mousewheel",
	$magnifier: {outer:null, inner:null, image:null},
	activeimage: null,

	movemagnifier:function(e, moveBol, zoomdir){
		var activeimage=ddpowerzoomer.activeimage 
		var activeimginfo=activeimage.info
		var coords=activeimginfo.coords 
		var $magnifier=ddpowerzoomer.$magnifier
		var magdimensions=activeimginfo.magdimensions 
		var power=activeimginfo.power.current
		var powerrange=activeimginfo.power.range
		var x=e.pageX-coords.left 
		var y=e.pageY-coords.top
		if (moveBol==true){
			if (e.pageX>=coords.left && e.pageX<=coords.right && e.pageY>=coords.top && e.pageY<=coords.bottom)  
				$magnifier.outer.css({left:e.pageX-magdimensions[0]/2, top:e.pageY-magdimensions[1]/2})	
			else{ 
				ddpowerzoomer.activeimage=null
				$magnifier.outer.hide() 
			}
		}
		else if (zoomdir){
			var od=activeimginfo.dimensions 
			var newpower=(zoomdir=="in")? Math.min(power+1, powerrange[1]) : Math.max(power-1, powerrange[0]) 
			var nd=[od[0]*newpower, od[1]*newpower]
			$magnifier.image.css({width:nd[0], height:nd[1]})
			activeimginfo.power.current=newpower 
		}
		power=activeimginfo.power.current
		var newx=-x*power+magdimensions[0]/2
		var newy=-y*power+magdimensions[1]/2
		$magnifier.inner.css({left:newx, top:newy}) 
	},

	setupimage:function($, imgref, options){
		var s=jQuery.extend({}, ddpowerzoomer.dsetting, options)
		var $imgref=$(imgref)
		imgref.info={ 
			power: {current:s.defaultpower, range:s.powerrange},
			magdimensions: s.magnifiersize,
			dimensions: [$imgref.width(), $imgref.height()],
			coords: null
		}
		$imgref.unbind('mouseenter').mouseenter(function(e){ 
			var $magnifier=ddpowerzoomer.$magnifier
			$magnifier.outer.css({width:s.magnifiersize[0], height:s.magnifiersize[1]}) 
			var offset=$imgref.offset() 
			var power=imgref.info.power.current
			$magnifier.inner.html('<img src="'+options.largeimagesrc+'"/>')
			$magnifier.image=$magnifier.outer.find('img:first')
				.css({width:imgref.info.dimensions[0]*power, height:imgref.info.dimensions[1]*power})
			var coords={left:offset.left, top:offset.top, right:offset.left+imgref.info.dimensions[0], bottom:offset.top+imgref.info.dimensions[1]}
			imgref.info.coords=coords 
			$magnifier.outer.show()
			ddpowerzoomer.activeimage=imgref
		})
	},

	
	init:function($){
		var $magnifier=$('<div style="position:absolute;width:100px;height:100px;display:none;overflow:hidden;border:1px solid black;z-index:1000" />')
			.append('<div style="position:relative;left:0;top:0;" />')
			.appendTo(document.body) 
		ddpowerzoomer.$magnifier={outer:$magnifier, inner:$magnifier.find('div:eq(0)'), image:null} 
		$magnifier=ddpowerzoomer.$magnifier
		$(document).unbind('mousemove.trackmagnifier').bind('mousemove.trackmagnifier', function(e){
			if (ddpowerzoomer.activeimage){ 
				ddpowerzoomer.movemagnifier(e, true) 
			}
		}) 

		$magnifier.outer.bind(ddpowerzoomer.mousewheelevt, function(e){ 
			if (ddpowerzoomer.activeimage){
				var delta=e.detail? e.detail*(-120) : e.wheelDelta 
				if (delta<=-120){ //zoom out
					ddpowerzoomer.movemagnifier(e, false, "out")
				}
				else{ //zoom in
					ddpowerzoomer.movemagnifier(e, false, "in")
				}
				e.preventDefault()
			}
		})
	}
} 

jQuery.fn.addpowerzoom=function(options){
	var $=jQuery
	return this.each(function(){ 
		if (this.tagName!="IMG")
			return true 
		if (typeof options=="undefined")
			options={}
		if (options.largeimage && options.largeimage.length>0){ //preload large image
			options.preloadimg=new Image()
			options.preloadimg.src=options.largeimage
		}
		var $imgref=$(this)
		options.largeimagesrc=(options.preloadimg)? options.preloadimg.src : $imgref.attr('src')
		if (parseInt(this.style.width)>0 && parseInt(this.style.height)>0) //if defined css width height other than default
			ddpowerzoomer.setupimage($, this, options)
		else if (this.complete){ //account for IE not firing image.onload
			ddpowerzoomer.setupimage($, this, options)
		}
		else{
			$imgref.bind('load', function(){
				ddpowerzoomer.setupimage($, this, options)
			})
		}
	})
}

jQuery(document).ready(function($){ //initialize zoom on DOM load
	ddpowerzoomer.init($)
})