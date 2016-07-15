title: "Dalvik Virtual Execution with SmaliVM"
tags:
  - dalvik
  - android
comments: true
date: 2016-04-30 00:00
author: caleb
---

Sometimes it's useful to know what code does without executing it. You could read the code with your eyeballs and run it with your brain but that takes too long and it's really hard, and executing code on a real machine can get messy, especially if it's malicious. But what can you do if you want to understand a lot of malicious code? What if it's obfuscated and even harder for your brain? Maybe you want to do some fancy analysis so you can accurately know when certain methods are called? Well, for this there's executing on a _virtual_ machine, i.e. virtual execution. There are many different ways of implementing a virtual machine. You could simulate an entire computer like  VirtualBox and QEMU or you could simulate a smaller subset. The general idea is the same between all types: build a program which simulates executing other programs in all the important ways and gracefully fails for everything else.
<!-- more -->

# What is SmaliVM?

SmaliVM is a virtual machine which emulates the Dalvik instruction set. It allows you to run Android apps in a limited and controlled way. Unlike the actual Dalvik virtual machine on an Android device, smalivm can execute methods _even if it doesn't know the arguments_. You can tell it to execute `foo(String s)` without giving it `s`. You might be wondering, "What happens if you have something like `if (s == null)` Does smalivm explode into little bits?" Ahh, that's where the fun begins. If a conditional is unknown, smalivm assumes it could be either true or false and takes both execution paths (multiverse!). After smalivm runs a method, it returns an execution graph which has a node for each instruction of every possible execution path. Nodes have parents and children and ancestry is defined by execution order. If a node has multiple children, it's execution path is not entirely certain. Each node can be inspected to learn the method, class, and virtual machine state at that point of the program.

# What's the point?

I wanted to make a generic deobfuscator. I spent a lot of time squinting at obfuscated malware code. It sucked. So, I made a few specialized deobfuscators; one for each new variant of malware. Any time I solve some problem, I try to generalize the solution. Past experience has taught me this is a badass way fully understand a problem. My first attempt at a general purpose deobfuscator was [Oracle](https://github.com/CalebFenton/dex-oracle) which I used to analyze a DexGuard protected Obad malware. It looks for patterns in code using regex and tries to simplify them. It gets some extra help by executing certain methods in the analyzed code using reflection on an emulator or device. It works decently and it's simplicity means it's easier to add new deobfuscation plugins, but since it uses regex, it's brittle; one small change in the obfuscator would require modifying a big, mean, ugly regex that would make part of you die if you stared at it for too long.

Without knowing anything about formal program analysis (or Java, #yolo), I started building what I hoped would be the ultimate generic Android deobfuscator: [Simplify](https://github.com/CalebFenton/simplify). The goal was to implement some instructions so it could execute code, understand what it does, and replace complex patterns with simplified versions. I figured it would take a few weeks of solid work to start using it to kick malware ass. Turns out, virtual execution isn't the sort of thing that partially works; it either works perfectly or fails spectacularly. All in all, it took ~21k lines of code from 550 commits over 2.5 years to get to a 1.0 release. Had some help from [@timstrazz](https://twitter.com/timstrazz) (unit tests!), [@\_jsoo\_](https://twitter.com/_jsoo_) (bugs!), [@OngEmil](https://twitter.com/OngEmil) and [@crufia](https://twitter.com/crufia) (how to java good). Thanks!

To see some slides for a talk I've done on this already, check out: [Android Deobfuscation: Tools and Techniques](/2016/04/23/tetcon-2016-android-deobfuscation/)

# Example SmaliVM Usage

I was advised by my [marketing team](/images/dalvik-virtual-execution-with-smalivm/Salesman-1.png) that I should include a simple yet impressive example of smalivm usage. This gives you the impression that I've neatly boiled down a complex problem into a simple, easy to use interface which will solve all your problems in just a few lines. Here:

```java
String smaliOrDexPath = "classes.dex";
VirtualMachineFactory vmFactory = new VirtualMachineFactory(); // this is Java, so factory
VirtualMachine vm = vmFactory.build(smaliOrDexPath);

String methodSignature = "Lorg/cf/example/Main;->foo(Ljava/lang/String;)V";
ExecutionGraph graph = vm.execute(methodSignature);
```

The above code will parse the `classes.dex` file and execute `org.cf.example.Main.foo(String s)` without defining what the value of `s` is. This means that the `graph` may contain multiple execution paths and if any instructions use `s` the values won't be known.

To execute with an actual argument, you just spawn a context and setup the method state:

```java
VirtualMachineFactory vmFactory = new VirtualMachineFactory();
VirtualMachine vm = vmFactory.build("classes.dex");

String methodSignature = "Lorg/cf/example/Main;->foo(Ljava/lang/String;)V";
ExecutionContext ectx = vm.spawnRootExecutionContext(methodSignature);
MethodState mState = ectx.getMethodState();
mState.assignParameter(0, "wubalubadubdub", "Ljava/lang/String;");

ExecutionGraph graph = vm.execute(methodSignature, ectx);
```

The `graph` object will contain a whole bunch of stuff you could dig into to figure out exactly what happens at every instruction.

# The Execution Graph

Executing a method with smalivm returns an execution graph which contains everything that Simplify needs to optimize the code, which is just about everything. Consider the following Smali code:

```smali
.method public static dumbMath()I
    .locals 2

    const/4 v0, 0x3
    const/4 v1, 0x5
    add-int/2addr v0, v1

    return v0
.end method
```

If you're unfamiliar with Smali, _how did you find this blog and why are you still here?_, otherwise you should know `dumbMath()I` returns 8. Here's a simplified version of what the execution graph would look like.

![](/images/dalvik-virtual-execution-with-smalivm/ExecutionGraph-dumbMath.png)

It's simple. Each node is an instruction and contains the values for all registers (after the instruction executes). Looking up register values enables most of the optimizations in Simplify.

Nodes are indexed by address, but it's not part of these graph images to keep them simple.

Now I want to show you what a conditional looks like:

```smali
.method public static sometimesReturnTwo(I)I
    .locals 1

    const/4 v0, 0x1
    if-eq p0, v0, :end

    add-int/2addr v0, v0

    :end
    return v0
.end method
```

If `p0` equals `0x1` then it returns `v0` which is 1. Otherwise, it returns 2. If you execute this method with a set value for `p0` of `0x1`, the execution graph will look like:

![](/images/dalvik-virtual-execution-with-smalivm/ExecutionGraph-loopy.png)

If you don't provide any value for `p0`, it's unknown and the execution graph is:

![](/images/dalvik-virtual-execution-with-smalivm/ExecutionGraph-loopy2.png)

Now you can start to see how graph analysis gets complicated. The `if-eq p0, v0, :end` node has two children. This means that there is a multiverse; there are multiple execution paths; there's ambiguity in the behavior of the method. SmaliVM executes both paths. Either the return value is 1 or it's 2. If a particular address in a graph has multiple nodes in the "node pile" then you can be sure there was either a loop or there was some conditional uncertainty.

You can get the return value of the method with Java code similar to:

```java
HeapItem item = graph.getTerminatingRegisterConsensus(MethodState.ReturnRegister);
item.getValue() // UnknownValue - means there was no consensus
item.getType() // I - type inferred from method return value
```

The `ExecutionGraph#getTerminatingRegisterConsensus(int register)` method will conveniently determine all of the terminating addresses for a method since there may be multiple return statements or exceptions. But you could also use the more generic `ExecutionGraph#getRegisterConsensus(int address, int register)`.

# Unknown Values

Values which aren't known are represented by an `UnknownValue` object. For example, if you execute a method without providing arguments, then `UnknownValue` objects are used as place holders. Other ways you might run into `UnknownValue`s:

* return value of blacklisted method, e.g. file and network I/O
* return value of method which fails to execute
* `iget` instructions - Non-static member value lookups are tricky because smalivm prefers to be correct even if that means having more unknown values. It's very hard to know if an object's members are modified in a separate thread.
* mutable arguments to a method which can't be executed - Since smalivm gave up on the method, it can't be sure they weren't mutated.

All operations are _aware_ of `UnknownValue`s and most operations that involve them result in a new `UnknownValue`. Check it:

```java
x = UnknownValue;
y = 10;
z = x + y; // z is unknown!
```

# Loops

When simulating a language which has loops and where you might not know the value of every variable, you run into the problem of not being able to determine when a loop finishes. Here's a simple example:

```java
private int loopy(int iterations) {
    int x = 1;
    for (int i = 0; i < iterations; i++) {
        x += x;
    }

    return x;
}
```

If you simulate the above code without knowing what `iterations` is, you can't be sure when the `for` loop condition of `i < iterations` will be true.

Story time: When I first encountered this problem, I'd already solved several seemingly impossible problems so I figured there was probably some clever way to solve this in general. Maybe I could carefully analyze the conditionals? Maybe I could look for loop invariants, or take into account maximum values, or maybe somehow extrapolate constraints on the range of values a method was likely to receive. I'd been working on it for about two days when a friend walked by, saw me starting at my notebook and asked what I was doing. After I gave a quick explanation of the project and problem he said, without any sarcasm, "Oh, cool! Yeah, that's the halting problem. Turing proved it was unsolvable, but good luck!" and he walked away.

So I deal with loops the same way everyone else does -- with configurable limits! For example, you can set the maximum:

1. number of times to execute a particular instruction
2. number of times a method can be called
3. call depth
4. execution time

With these limits in place, if the above code was executed, smalivm would "give up" after several tens of thousands of iterations, correctly assuming it's impossible to know when it would finish. If `loopy` was the entry point method, the `graph` return value would end up as `null`, since it failed. But if `loopy` was called as part of the flow of some other method, it would return an unknown value to the calling method and any operations that interacted with that value would then also be marked unknown.

# Side Effects

A method is said to have side effects if it affects the state of something outside the method. This could be anything from network or file IO, calling an unsafe method (i.e. probably does some I/O), changes class or object state, etc. and smalivm keeps track of the side effects of each instruction.

SmaliVM has three categories of side effects:

1. none - reflected, emulated, or whitelisted methods and safe ops, e.g. const/4
2. weak - not white listed, used when there _may_ be a side effect
3. strong - changes something like a class or object member

Simplify uses side effect strength to know if it's OK to remove code. If method A calls method B, and B just does some math and returns the result, then it may be possible to simply inline the return value of B inside of A and avoid calling B all together. To understand inlining, consider this code:

```java
A() {
    int x = 5;
    int y = B(x);
}

B(int x) {
    return x ** x;
}
```

Since `B()` does jack all except some math and has no side effects, it can be inlined:

```java
A() {
    int x = 5;
    int y = 25;
}
```

On the smali level, the `invoke` instruction is replaced with a `const*` instruction. However, if a method calls another method which writes to the file system, well then it can't be removed because Simplify can't be sure removing that method won't alter the behavior of the program. This'll be explained a lot more in future posts about how Simplify works.

# Exception Handling

Exception is handling adds all kinds of complexity. If someone ever tells you they wrote a program which emulates Java or Dalvik code and you want to be a dick, smugly ask them how they handle exceptions. Also, ask them how the handle multi-threadding, but that's for another post.

You have to build each instruction so it knows when to throw an exception and how to make it look real. Then, as you're walking along the instructions executing stuff, you have to be aware of where to jump if you hit an exception, e.g. `try / catch` blocks. The real kicker is that exceptions have to bubble up the call stack. If you call method A which calls method B which calls method C which throws an exception, the ultimate handler for that exception might be method A.

As of now, exception handling is mostly working and if there's some major bugs it should be possible to fix without major re-designs. Fingers crossed, yo.

Also, if an instruction is executed with unknown values, it's assumed the instruction throws an exception. This can cause a lot of ambiguity in the execution paths, but it's the only way to really ensure correctness.

# Deobfuscation

This post is already really long, but I wanted to show you an example of the obfuscation that originally motivated smalivm:

```java
public void doBadStuff() {
    int x;
    int y;
    x = Integer.valueOf("5")
    y = Integer.valueOf("10")
    x = x * y;
    x += 5;
    x /= 3;
    hackYourPhoneLOL("backdoor");
    x = y;
    y = x + 10;
    y /= 2;
}
```

This is a semi-realistic example of a type of obfuscation called "arithmetic white noise" because it's just a bunch of bullshit math operations that don't actually affect the state of the app outside the method. In other words, it has no side effects. The math stuff doesn't affect the return value of the method since there isn't one, and it doesn't affect the `hackYourPhoneLOL()` method. Just looking at the code, you can figure out you could just rewrite much simpler and not affect the semantics (behavior, what it does):

```java
public void doBadStuff() {
    hackYourPhoneLOL("backdoor");
}
```

I'll be diving deeper into this in later posts.

# Hooking Methods

Hooking methods is pretty easy. You just need to make a class which implements `MethodStateMethod` if it only needs access to local method state or `ExecutionContextMethod` if it needs access to the entire virtual machine state. Here is hook for `System.out.println()` :

```java
public class java_io_PrintStream_println implements MethodStateMethod, UnknownValuesMethod {

    @Override
    public void execute(VirtualMachine vm, MethodState mState) {
        // Virtual method, register 0 is System.out (or something else)
        HeapItem item = mState.peekParameter(1);
        Object value = item.getValue();
        String valueStr = (String) value;

        // Actually print out any println's executed.
        System.out.println(valueStr);
    }

    public SideEffect.Level getSideEffectLevel() {
        // Do not optimize this away.
        return SideEffect.Level.STRONG;
    }

    @Override
    public Set<VirtualException> getExceptions() {
        return new HashSet<VirtualException>();
    }

}
```

And here's how to configure the hook:

```java
String hookSignature = "Ljava/io/PrintStream;->println(Ljava/lang/String;)V";
MethodEmulator.addMethod(hookSignature, java_io_PrintStream_println.class);

// Build and execute VM
```

# Optimizations

The code isn't really optimized right now because I've favored working on correctness. But there are a few optimizations that are important for understanding how smalivm works.

## Sparse Contexts

As you've seen in the execution graph section, nodes have parent / child relationships. Rather than store all of the values for every register in every node, only changes are stored. This saves a ton of space, but if you want to know the value of a particular register at some node, you may have to dig through its parents, grandparents (ancestors) until you find a node which has it. This is a memory / time trade off. It accounts for a lot of processing time, but without it, graphs would blow out the heap constantly.

## Reflection

Any time smalivm needs to execute a method which is part of the Java API and is safe to execute, it'll use Java reflection to execute it. For a method to be safe, it can't have any side effects and basically can't be used to a clever malicious person to own your system. For example, smalivm will reflect `Integer.valueOf()`, all `String` and `StringBuilder` methods, and some others. This is useful for two reasons:

1. it's way faster
2. Java API code has fewer bugs than mine

## Dynamic Class Generation

For all input classes, smalivm will try to build a realistic looking Java `Class` object for that class. It should have all the same methods, fields, access flags, etc. Whenever smalivm executes code that gets a `Class` object for an input class, it provides the dynamically generated `Class` object. This allows smalivm to reflect Java API methods which take classes defined _by the input Smali or DEX_.

# Other Emulators

The main related emulator I'm aware of is [Unicorn](http://www.unicorn-engine.org/) which is super cool and you should check it out. It does a lot more than smalivm, but it's based on QEMU so it supports lots of different architectures but not the DalvikVM or JavaVM.

# Future Ideas

I have some ideas that I think would be cool but I haven't had much time to implement them.

## Interactive Debugger

I've used smalivm to debug Android apps, but it required me knowing a lot about how the code works and setting lots of break points in my IDE. It should be possible to generalize some of smalivm's functionality and wrap it up in a nice little debugging UI. One would be able to inspect or modify values, step through the code instruction by instruction, or set break points, watch registers, dynamically hook methods, set return values for methods, and so much more. Since smalivm only has one project that uses it right now, adding another would really help smooth the edges and clean up the cobwebs around the code base, and would really make the library more generalized and easier to use.

## Android Component Lifecycle Awareness

Right now smalivm executes methods in a somewhat random order which is easy but it has a lot of downsides. The main drawback is that instance variables are difficult to know. Consider an Android activity that sets up some instance variables in the `onCreate()` method. Later, they're accessed in `someHelperMethod()`. Since smalivm may execute `someHelperMethod()` first, it never gets the instance variables setup properly. For this and a few other reasons, smalivm doesn't track instance variables at all.

If smalivm was smart enough to know that any time it executes a method for an activity, it should first execute other methods which would ordinarily be executed firsts, e.g. `onCreate()`, `attachBaseContext()`, etc., then it would be possible to much more reliably determine instance variable values.

# Summary

Thanks for getting this far, even if you skipped to the end without reading anything. I hope you found it interesting and you give smalivm and Simplify a look. Maybe you can make use of it. If you do, holla.

Stay tuned for future posts which will explain how Simplify uses smalivm to deobfuscate.
