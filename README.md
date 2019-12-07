# HookedRDP
This dll is used to hook Windows' RDP client to snag information about the credentials and the server being connected to.  

This is a post exploitation type deal and you will need to inject the DLL somehow. There are numerous ways of doing so, and that will be left up to you to do. For now, this just uses the regular ol' MessageBox just as a PoC. The goodies I have done are not on here :)

I had some issues with compiling and what not so kind of refactored a little code and added a thing or two to make it work with Win7 and Win10. It's compiled using Visual Studio 2019 
