# HookedRDP
This dll is used to hook Windows' RDP client to snag information about the credentials and the server being connected to. You can check it out by reading their blog to get an idea of what exactly it does:  https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/. I'm not cool enough to use Cobalt Strike though..

This is a post exploitation type deal and you will need to inject the DLL somehow. There are numerous ways of doing so, and that will be left up to you to do. For now, this just uses the regular ol' MessageBox just as a PoC. The goodies I have done are not on here :)

I had some issues with compiling their code and what not so kind of refactored a little code and added a thing or two to make it work with Win7 and Win10. It's compiled using Visual Studio 2019   

![thingy](https://github.com/ch3rn0byl/HookedRDP/blob/master/Image/what.png)

Update: The encrypted text coming along   

![thingy](https://github.com/ch3rn0byl/HookedRDP/blob/master/Image/Capture1.PNG)    

Update: A client has been made to decrypt the output of the loot    

![thingy](https://github.com/ch3rn0byl/HookedRDP/blob/master/Image/dec.PNG)    

# TO-DO  
Make a client/server type deal that way I can snag it remotely? That would be nice af
And more, because this is a work in progress
