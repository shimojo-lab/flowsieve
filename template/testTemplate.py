from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("./"))
tpl = env.get_template("xsupplicant.tpl.conf")

conf = tpl.render({"if_name": "h1-eth0", "mac_addr": "xx-xx-xx-xx-xx-xx"})
print conf
