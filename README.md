# yamada-ofcontroller

[![Build Status](http://drone.ais.cmc.osaka-u.ac.jp/api/badges/core-grid/yamada-ofcontroller/status.svg)](http://drone.ais.cmc.osaka-u.ac.jp/core-grid/yamada-ofcontroller)

"ロールベースセキュリティポリシーを持つネットワーク"のためのOpenFlowコントローラ

## Open vSwitch + KVM / 物理OpenFlowスイッチ + 物理サーバ

### 環境設定

1. Python, pip, virtualenvをインストールする
2. [direnv](https://github.com/direnv/direnv) をインストール・設定する
3. このリポジトリをcloneし、ディレクトリ内に移動する
4. `direnv allow`
5. `pip install -r requirements.txt`
6. 各OpenFlowスイッチがコントローラを実行するマシンのTCP/6633番ポートに接続
  するように設定

### 実行

1. `./tool/run_controller`

## Vagrant + mininet

### 環境設定

1. [Vagrant](https://www.vagrantup.com/) と [Ansible](https://www.ansible.com/)
  をインストールする
2. このリポジトリをcloneし、`tool/` ディレクトリ内に移動する
3. `vagrant up`
4. `vagrant ssh`

### 実行

以下は `vagrant ssh` でログインした仮想マシン内で実行する。

1. `cd /vagrant`
2. `./tool/run_controller` (フォアグラウンドで実行するので以下は別セッション)
3. `sudo ./tool/run_network`

