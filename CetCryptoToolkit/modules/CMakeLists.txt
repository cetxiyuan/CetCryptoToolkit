
# 头文件路径 
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/certificatemanager 
)

file(GLOB SOURCES */*.cpp)
file(GLOB HAEDERS */*.h)
file(GLOB FORMS */*.ui)	

target_sources(${PROJECT_NAME} PRIVATE 
	${SOURCES}
	${HAEDERS}
	${FORMS}
)

