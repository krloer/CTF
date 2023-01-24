function executeCommand(){
    var chat = document.getElementById('chat').value;
    var command = chat.split(" ")[0];
    var value = chat.split(" ")[1];
    var resultField = document.getElementById("result");
    switch(command){
        case '/r':
            var quantity = parseInt(value.split("d")[0]);
            var sides = parseInt(value.split("d")[1]);

            var result = 0;

            for(var i=0; i<quantity; i++){
                result += Math.floor(Math.random() * sides) + 1;
            }
            
            var masterName = "master@fdb73dc7-d4cc-4fdb-bf3e-729878f35665.com";

            if(result > (sides + 1)/2 * quantity){
                var resultString = "<strong>" + masterName.split('@')[0] + "</strong>: Your result is " + result + ". Wow you rolled above average! Unfortunately, I am not able to play now. See you soon";
            }else{
                var resultString = "<strong>" + masterName.split('@')[0] + "</strong>: Your result is " + result + ". Not a great roll, let's see what happens. Unfortunately, I am not able to play now. See you soon";
            }
            resultField.innerHTML = resultString;
            break;
        default:
            resultField.innerHTML = "Command not known :("
    }
}