Vagrant.configure("2") do |config|
  config.vm.box = "mwrock/Windows2019"
  config.vm.define "dc01" do |dc|
    dc.vm.hostname = "dc01"
    dc.vm.network "private_network", ip: "192.168.56.10"
    dc.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
  end
end
