** Warning - this is still under active development and is incomplete**

Bigip config to terraform plan file converter

This project perfroms two things:
1. It parses a bigip via a the REST interface using the F5 SDK and pulls the configuration from it.  Currently, it limits the configuration only to the items that are possible to declare in a Terraform plan.  There are some some things that need to be resolved in a 'clever' manner so its not adivsed to assume this could directly be used to configure a bigip with these items without carefully addressing those 'clever' implementations (namely in sub collections)
2. It the writes out Terraform plans (.tf files) for each object.  Since Terraform will load all tf files found in a directory, this made the most sense.




