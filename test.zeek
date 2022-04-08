global my_table : table[addr] of set[string];
global my_table_len : table[addr] of int;
event http_reply(c: connection, version: string, code: count, reason: string){
	local my_ip :addr =c$id$orig_h;
    local my_agent :string =c$http$user_agent;
    if(my_ip !in my_table)
    {
    	my_table[my_ip]=set(my_agent);
    	my_table_len[my_ip]=1;
    }
    else
    {
    	if(my_agent !in my_table[my_ip])
    	{
    		add my_table[my_ip][my_agent];
    		my_table_len[my_ip]=my_table_len[my_ip]+1;
    	}
    }
    


}
event zeek_done()
{
	# local x:int =1;
	for(key in my_table_len)
	{
		if(my_table_len[key]>3)
		{
		
		print "alert";
		break;
		}
	}
}
