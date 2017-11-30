module Scan;

export 	{

	redef enum Notice::Type += {
                VNCScanner, 
	} ; 

	global rfb_dst: table[addr] of set[addr] &create_expire=12 hrs ; 
	global rfb_scanners: table[addr] of count &default=0 ;
	} 
	 
event connection_state_remove(c: connection) &priority=-5
{
	if (c$id$orig_h in Site::local_nets )
		return ; 

	if (c$id$orig_h in rfb_scanners)
	{ 
		++rfb_scanners[c$id$orig_h] ; 
		return ; 
	} 

        if ( c?$rfb )
	{ 
		local src = c$rfb$id$orig_h ; 
		local dst = c$rfb$id$resp_h ; 
		
		if (src !in rfb_dst)
		{
			local a: set[addr] ; 
			rfb_dst[src]= a; 
		} 

		add rfb_dst[src][dst]; 
		
		if ( c$id$orig_h !in rfb_scanners && |rfb_dst[src]| > 4) { 

			local iplist = "" ;
			for (ipl in rfb_dst[src])
				iplist += fmt (" %s,", ipl) ; 
                        NOTICE([$note=Scan::VNCScanner,
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt ("%s has hit %s IPs on vnc %s", src, iplist, c$id$resp_p), 
                                $identifier=cat(c$id$orig_h)]);
                        
			++rfb_scanners[c$id$orig_h];
		} 

	} 
} 

	

