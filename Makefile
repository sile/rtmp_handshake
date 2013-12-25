all: compile eunit                                                   

compile:
	@./rebar compile

xref:
	@./rebar xref

clean:
	@./rebar clean

eunit:
	@./rebar eunit

edoc:
	@./rebar doc

.dialyzer.plt:
	touch .dialyzer.plt
	dialyzer --build_plt --plt .dialyzer.plt --apps erts kernel stdlib inets crypto compiler

dialyze: .dialyzer.plt
	dialyzer --plt .dialyzer.plt -r ebin
