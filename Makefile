test: mocks
	./test.sh

mocks: grant_mocks token_mocks

grant_mocks:
	@mockery                \
        -case=underscore    \
        -all                \
        -dir=grant          \
        -output=mocks       \

token_mocks:
	@mockery                \
        -case=underscore    \
        -all                \
        -dir=token
        -output=mocks       \
