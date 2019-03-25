** Warning - this is still under active development and is incomplete**

This project performs two things:

1. It parses a BigIP via a the REST interface using the F5 SDK and pulls the configuration from it. Currently, it limits the configuration only to the items that are possible to declare in a Terraform plan. There are some some things that need to be resolved in a 'clever' manner so its not advised to assume this could directly be used to configure a bigip with these items without carefully addressing those 'clever' implementations (namely in sub collections)
2. It the writes out Terraform plans (.tf files) for each object. Since Terraform will load all tf files found in a directory, this made the most sense.

github link is below:

https://github.com/caliraftdude/f5-terraform


Currently there are still some major issues..

1. Because of the odd way that monitors are accumulated and parsed via a REST interface, and the recursiveness of the routines necessary to pull apart various sub-collections, it creates a problem in the OBJECT_LIBRARY and thus complicated the expected output.  At this point, monitors are NOT exported into a config file.
2. There are a number of "NOT IMPLEMENTED" areas in the config where issues need to be worked around or it wasn't clear how you would translate an item.  When idle time permits I'll attempt to tighten this up but at this point there are a few areas that need to be reviewed before using a plan.
3. The parsing routine has had a couple of re-writes and this was namely in dealing with weird, bizarre and inconsistent issues with the python/REST SDK.  Some of this was sorted out while writing the parser and others had to be reviewed/rewritten during the tf-output routines.  Because of this - the parser should really be reviewed and re-factored but at this time its considered 'good enough'. 
4. Along with #3 - cleaning up this routine would enable creating output routines for other tools like Ansible and so on to be reliably built into the tool.
5. The "main" part of the function is very simplistic.. it just asks for username/pass/destination.  In actuality, it would be better if these elements were accepted on the command line with a number of options (getopt..) and possibly the allowance of sucking of a CSV full of u/p/IP rows in order to bulk convert configs.  This, however, is a bit less important until other areas of the tool are cleaned up/matured.
6. It would also be good if the tool checked if terraform was installed/accessible and to test the plan files outputting problems that need to be corrected before use.
7. Lastly - the documentation for Terraform ( https://www.terraform.io/docs/providers/bigip/index.html) is not real good and items in the plan seem to not line-up with what a config file is capable of describing.  I don't know if this is a problem with documentation or if the API is just not as mature.  That being said, the tool really should create a log file that states *what* is not converted so if additional cleanup work needs to be done its obvious what needs to be done.
8. There may be other issues...  ;)


