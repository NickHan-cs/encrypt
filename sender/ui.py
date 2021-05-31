import tkinter as tk
import os
from subprocess import Popen, PIPE
# os.chdir("./sender")
os.system("make")
root = tk.Tk()
root.geometry('800x600')
root['background'] = 'white'
root.wm_title("发送端")
# IP地址
ipLabel = tk.Label(root, text="IP:", bg='white')
ipLabel.place(x=80, y=60, width=100, height=40)
ipAddr = tk.StringVar()
ipEntry = tk.Entry(root, textvariable=ipAddr, relief='flat')
ipAddr.set('192.168.31.128')
ipEntry.place(x=150, y=60, width=200, height=40)
# 端口
portLabel = tk.Label(root, text="端口:", bg='white')
portLabel.place(x=400, y=60, width=100, height=40)
portNum = tk.StringVar()
portEntry = tk.Entry(root, textvariable=portNum, relief='flat')
portNum.set('8888')
portEntry.place(x=470, y=60, width=200, height=40)
# 文件列表
snd_list = tk.Listbox(root, relief='flat')
sb = tk.Scrollbar(snd_list)
sb.pack(side=tk.RIGHT, fill=tk.Y)
snd_list['yscrollcommand'] = sb.set
snd_list.place(x=180, y=270, height=200, width=440)
sb.config(command=snd_list.yview)
# 文件地址
fileLabel = tk.Label(root, text="文件地址:", bg='white')
fileLabel.place(x=160, y=200, width=100, height=40)
filePath = tk.StringVar()
fileEntry = tk.Entry(root, textvariable=filePath, relief='flat')
filePath.set('')
fileEntry.place(x=250, y=200, width=230, height=40)
# 添加文件


def addFile():
    global filePath
    snd_list.insert(tk.END, filePath.get())
    print(snd_list.get(0, snd_list.size()-1))
    filePath.set('')
# 打开文件


def openFile(filePath):
    another = tk.Toplevel()
    another.geometry('400x300')
    with open(filePath) as file_obj:
        content = file_obj.read()
    lb = tk.Label(another, text=content, width=400, height=10,
                  anchor='w', justify='left', wraplength=400,)
    lb.pack()
    another.mainloop()
# 发送文件


def send():
    while snd_list.size() > 0:
        f = snd_list.get(0)
        p = Popen(["./send", ipAddr.get(), portNum.get(), f], stdout=PIPE)
        output = p.stdout.read().decode()
        print(output)
        snd_list.delete(0)


def out():
    # print("记得删除seed.txt")
    os.chdir("..")
    os.system("rm seed.txt")
    root.destroy()


# 添加文件按钮
addFileBtn = tk.Button(root, text='添加', command=addFile,
                       relief='flat', bg='white')
addFileBtn.place(x=520, y=200, width=100, height=40)
# 删除文件按钮
delFileBtn = tk.Button(root, text='删除', command=lambda x=snd_list: x.delete(
    tk.ACTIVE), relief='flat', bg='white')
delFileBtn.place(x=180, y=500, width=100, height=40)
# 文件打开按钮
openFileBtn = tk.Button(root, text='打开', command=lambda x=snd_list: openFile(
    x.get(tk.ACTIVE)), relief='flat', bg='white')
openFileBtn.place(x=520, y=500, width=100, height=40)
# 发送文件按钮
sndBtn = tk.Button(root, text='发送', command=send, relief='flat', bg='white')
sndBtn.place(x=180, y=140, width=100, height=40)
# 退出按钮
quBtn = tk.Button(root, text='退出', command=out, relief='flat', bg='white')
quBtn.place(x=520, y=140, width=100, height=40)
root.mainloop()
