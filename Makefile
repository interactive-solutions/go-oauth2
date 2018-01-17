test: mocks
	./test.sh

mocks: grant_mocks service_mocks model_mocks

grant_mocks:
	@mockery                \
        -case=underscore    \
        -all                \
        -dir=grant          \
        -output=mocks       \

service_mocks:
	@mockery                \
        -case=underscore    \
        -all                \
        -dir=service
        -output=mocks       \

model_mocks:
	@mockery                \
        -case=underscore    \
        -all                \
        -dir=model
        -output=mocks       \


