# yamada-ofcontroller

[![Build Status](http://drone.ais.cmc.osaka-u.ac.jp/api/badges/core-grid/yamada-ofcontroller/status.svg)](http://drone.ais.cmc.osaka-u.ac.jp/core-grid/yamada-ofcontroller)

"ロールベースセキュリティポリシーを持つネットワーク"のためのOpenFlowコントローラ

## Open vSwitch + KVM or 物理OpenFlowスイッチ + 物理サーバ

実験用ネットワークは仮想マシン/仮想スイッチ、あるいは物理マシン/物理スイッチ
を用いて手動で構築する。direnv + virtualenvにより物理マシン上に隔離環境をつくり
、そこでコントローラを起動する。

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

VagrantによりUbuntuのVMを起動し、Ansibleで必要なコンポーネントを一括で
プロビジョニングする。VM内でmininetを起動し、仮想ネットワークをVM内に自動的に
構築する。コントローラはVM内で実行する。

### 環境設定

1. [Vagrant](https://www.vagrantup.com/) と [Ansible](https://www.ansible.com/)
  をインストールする
2. このリポジトリをcloneし、`tool/` ディレクトリ内に移動する
3. `vagrant up` (Ansibleによるプロビジョニングが実行される)
4. `vagrant ssh`

### 実行

以下は `vagrant ssh` でログインした仮想マシン内で実行する。

1. `cd /vagrant`
2. `./tool/run_controller` (フォアグラウンドで実行するので以下は別セッション)
3. `sudo ./tool/run_network`

---

This software is released under the Apache 2.0 License. See LICENSE for the
full license text. This software includes a part of a work that is distributed
in the Apache 2.0 License.

