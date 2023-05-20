#!/bin/bash
mkdir -p ./priv
cmd_exists(){
	local ret=0;
	command -v $1 >/dev/null 2>&1 || { local ret=1; }
	if [ "$ret" -ne 0 ]; then
		return 0;
	fi
	return 1
}
cmd_exists $HOME/.caro/bin/cargo
if [ $? -eq '0' ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    #source $HOME/.cargo/env
else
    echo "Rust already install."
fi
build(){
    mkdir -p ./priv
    $HOME/.cargo/bin/cargo build --manifest-path=crates/sui/Cargo.toml --release
    sh -c "cp $(cat crates/sui/libpath) ./priv/libsui.so "
}
test(){
    cargo test --manifest-path=crates/sui/Cargo.toml 
}
clippy(){
    cargo clippy --manifest-path=crates/sui/Cargo.toml 
}
help(){
    echo "sh build_crates.sh <command> :"
    echo "build              - do cargo build and cp libpath to priv"
    echo "test               - do cargo test"
    echo "clippy             - do cargo clippy to improve your rust code"
    echo "bench              - do cargo bench"
    echo "help               - help to use command"
}
bench(){
    cargo bench --manifest-path=crates/sui/Cargo.toml 
}
fmt(){
    cargo fmt --manifest-path=crates/sui/Cargo.toml 
}
update(){
    cargo update --manifest-path=crates/sui/Cargo.toml 
}
case $1 in
fmt) fmt;;
bench) bench;;
build) build;;
test) test;;
update) update;;
clippy) clippy;;
*) help;;
esac
