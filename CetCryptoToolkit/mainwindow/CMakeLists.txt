
# 头文件路径 
target_include_directories(${PROJECT_NAME} PRIVATE 
	${CMAKE_CURRENT_SOURCE_DIR}/
)

file(GLOB SOURCES *.cpp )
file(GLOB HAEDERS *.h )
file(GLOB FORMS *.ui )	

# 添加源文件
target_sources(${PROJECT_NAME} PRIVATE 
	${SOURCES}
	${HAEDERS}
	${FORMS}
)

