package com.bader88.springsecurity.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private static List<Todo> getTodos() {
    return List.of(new Todo("bader", "Learn Spring Security"),
            new Todo("bader", "Learn AWS"));
}
    @GetMapping("/todos")
    public List<Todo> getAllTodos() {
     return getTodos();
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return getTodos().get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Creating new todo for user {} with description {}", username, todo);

    }

}
record Todo(String username, String description){}
