//int getValueFromArray(int *array, int len, int index) {
void main() {

    int arr[5] = {1, 2, 3, 4, 5};
    int *array = arr;
    int len = 5;
    int index = -1;

    int value;

    if (index < len) {
        value = array[index];
    }

    else {
        printf("Value is: %d\n", array[index]);
        value = -1;
    }

    //return value;
}