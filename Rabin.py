import tkinter as tk
from tkinter import scrolledtext, messagebox
from rabin_lib import (
    miyao, JiaMi, JieMi, 

    add_random_letter_to_string,   
    string_to_unicode_with_tuple,
    filter_decrypt_combinations,
    get_reduced_alphabet,
    remove_letters_from_string,

    add_sequence_and_checksum_to_string,
    split_encoding,
    combine_and_verify,

    add_timestamp_to_unicode,
    verify_and_extract_characters
)
import string

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Herramienta de Cifrado y Descifrado Rabin")
        self.root.geometry("700x650")
        self.root.rowconfigure(0, weight=1)  # Configurar la única fila de la ventana principal
        self.root.columnconfigure(0, weight=1)  # Configurar la única columna de la ventana principal

        # Inicializar lista de cocientes
        self.shang = []
        # Inicializar almacenamiento de datos cifrados
        self.encrypted_data = {}
        
        # GUI
        self.setup_gui()

    def setup_gui(self):

        # Create a main frame that fills the entire window
        main_frame = tk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky='nsew')
        main_frame.rowconfigure(0, weight=0)  # Mode selection frame
        main_frame.rowconfigure(1, weight=0)  # Input frame
        main_frame.rowconfigure(2, weight=1)  # Display frame
        main_frame.rowconfigure(3, weight=0)  # Button frame
        main_frame.columnconfigure(0, weight=1)  # Only one column

        # Label method selection
        mode_frame = tk.Frame(main_frame)
        mode_frame.grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        mode_frame.columnconfigure(1, weight=1)  # Allow dropdown menu to expand

        mode_label = tk.Label(mode_frame, text="Seleccionar Método de Etiqueta:")
        mode_label.grid(row=0, column=0, padx=5,pady=5,sticky='w')

        self.mode_var = tk.StringVar(value='Método 1 (Letras Aleatorias)')
        mode_options = ['Método 1 (Letras Aleatorias)', 'Método 2 (Secuencia y Suma de Verificación)','Método 3 (Marca de Tiempo)']
        mode_dropdown = tk.OptionMenu(mode_frame, self.mode_var, *mode_options)
        mode_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Letter range selection (only for Method 1)
        self.range_frame = tk.Frame(mode_frame)
        self.range_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky='ew')
        self.range_frame.columnconfigure(1, weight=1)
        self.range_frame.columnconfigure(3, weight=1)


        start_label = tk.Label(self.range_frame, text="Letra Inicial:")
        start_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        self.letter_start = tk.StringVar(value='a')
        start_dropdown = tk.OptionMenu(self.range_frame, self.letter_start, *string.ascii_lowercase)
        start_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        end_label = tk.Label(self.range_frame, text="Letra Final:")
        end_label.grid(row=0, column=2, padx=5, pady=5, sticky='w')

        self.letter_end = tk.StringVar(value='f')
        end_dropdown = tk.OptionMenu(self.range_frame, self.letter_end, *string.ascii_lowercase)
        end_dropdown.grid(row=0, column=3, padx=5, pady=5, sticky='ew')

        # Place range_frame on the next row (row=1) of mode_frame
        self.range_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='w')

       # Bind mode change event
        self.mode_var.trace_add('write', self.update_range_frame_visibility)

        # Initialize range_frame visibility based on current mode
        self.update_range_frame_visibility()

        # Input frame
        entry_frame = tk.Frame(main_frame)
        entry_frame.grid(row=1, column=0, padx=10, pady=5, sticky='ew')
        entry_frame.columnconfigure(1, weight=1)

        entry_label = tk.Label(entry_frame, text="Por favor ingrese una cadena:")
        entry_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        self.entry = tk.Entry(entry_frame, width=80)
        self.entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Display frame
        self.result_box = scrolledtext.ScrolledText(main_frame, width=100, height=30, wrap=tk.WORD)
        self.result_box.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')
        self.result_box.configure(state='normal')


        # Button frame
        button_frame = tk.Frame(main_frame)
        button_frame.grid(row=3, column=0, padx=10, pady=10, sticky='ew')
        button_frame.columnconfigure((0,1,2), weight=1)  # Let three buttons share space equally

        # Botón de cifrar
        encrypt_button = tk.Button(button_frame, text="Cifrar", command=self.on_encrypt)
        encrypt_button.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

        # Botón de descifrar
        decrypt_button = tk.Button(button_frame, text="Descifrar", command=self.on_decrypt)
        decrypt_button.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Botón de limpiar
        clear_button = tk.Button(button_frame, text="Limpiar",command=self.clear)
        clear_button.grid(row=0, column=2, padx=5, pady=5, sticky='ew')

        # Agregar botón de información del programa
        info_button = tk.Button(main_frame, text="Información del Programa", command=self.show_info)
        info_button.grid(row=4, column=0, padx=10, pady=10, sticky='ew')

    def show_info(self):
        # Mostrar diálogo de información
        messagebox.showinfo("Información del Programa", """
        Esta es una herramienta de cifrado y descifrado Rabin. Puede elegir diferentes métodos de etiqueta para el cifrado y descifrado de cadenas:   
                                        
        Método 1: Cifrado mediante la adición de letras aleatorias.
                Implementación: Seleccionar aleatoriamente una de las 26 letras minúsculas del inglés, convertirla a codificación Unicode con un formato fijo de 4 dígitos. Por ejemplo, "a" se convierte en "0097" y se agrega a la codificación Unicode de cada carácter. Durante el descifrado, extraer los últimos cuatro dígitos y convertir a un carácter, luego verificar si está dentro del rango de letras seleccionado.
                            
        Método 2: Cifrado mediante números de secuencia y sumas de verificación.
                Implementación: Numerar cada carácter secuencialmente comenzando desde 0, con formato 0000 (número máximo de entrada 9999). Este número y la codificación Unicode del carácter de entrada se someten a operación hash. Los últimos cuatro dígitos del valor hash sirven como suma de verificación. Solo el código Unicode de los caracteres de entrada se cifra/descifra. Finalmente, realizar operación hash secuencialmente con los cuatro resultados obtenidos del descifrado de cada carácter y comparar con los últimos cuatro dígitos del valor hash correcto.
                            
        Método 3: Cifrado mediante marcas de tiempo.
                Implementación: Agregar un sufijo de marca de tiempo a cada carácter (preciso al año, mes, día, hora, minuto - 12 dígitos en total). La marca de tiempo se extrae y guarda como estándar de comparación posterior. El carácter completo (código Unicode + marca de tiempo) se cifra/descifra, y finalmente se compara la marca de tiempo en el resultado.

        Autor: Ni Shuo                                    
        """)


    def update_range_frame_visibility(self, *args):
        if self.mode_var.get() == 'Método 1 (Letras Aleatorias)':
            self.range_frame.grid()
        else:
            self.range_frame.grid_remove()


    def clear(self):
        self.entry.delete(0, tk.END)  # Limpiar cuadro de entrada
        self.result_box.delete(1.0, tk.END)  # Limpiar cuadro de visualización
        self.encrypted_data = {}  # Limpiar datos cifrados

    def on_encrypt(self):
        input_text = self.entry.get().strip()  # Obtener contenido del cuadro de entrada y eliminar espacios iniciales/finales

        if not input_text:
            messagebox.showwarning("Error de Entrada", "Por favor ingrese una cadena para cifrar.")
            return

        mode = self.mode_var.get()
        self.result_box.insert(tk.END, "=== Proceso de Cifrado ===\n\n")

        # Generar nuevas p y q para cada cifrado
        p, q = miyao()
        n = p * q
        self.result_box.insert(tk.END, f"Claves p y q generadas: {p}, {q}\n\n")

        if mode == 'Método 1 (Letras Aleatorias)':
            # Obtener rango de letras
            start = self.letter_start.get()
            end = self.letter_end.get()

            if start > end:
                messagebox.showwarning("Error de Rango", "La letra inicial no puede ser mayor que la letra final.")
                return

            letter_range = get_reduced_alphabet(start, end)

            # Agregar etiquetas de letras aleatorias
            encoded_string = add_random_letter_to_string(input_text, letter_range)
            self.result_box.insert(tk.END, f"Cadena procesada (cada carácter con una letra aleatoria añadida): {encoded_string}\n\n")  

            # Convertir a lista de enteros Unicode
            unicode_ints = string_to_unicode_with_tuple(encoded_string)
            self.result_box.insert(tk.END, f"Valores Unicode de la cadena procesada (entero): {unicode_ints}\n\n")

            # Realizar cifrado
            miwen, shang = JiaMi(unicode_ints, p, q)
            self.result_box.insert(tk.END, f"Valores Unicode del texto cifrado: {miwen}\n\n")
            self.encrypted_data['Método 1'] = {'miwen': miwen, 'shang': shang, 'p': p, 'q': q}

        elif mode == 'Método 2 (Secuencia y Suma de Verificación)':
            # Agregar etiquetas de número de secuencia y suma de verificación
            encoded_string = add_sequence_and_checksum_to_string(input_text)
            self.result_box.insert(tk.END, f"Cadena procesada (cada carácter con número de secuencia y suma de verificación): {encoded_string}\n\n")  

            prefixes, char_codes = split_encoding(encoded_string)
            self.result_box.insert(tk.END, f"Parte de número de secuencia y suma de verificación: {prefixes}\n")
            self.result_box.insert(tk.END, f"Parte de valor Unicode del carácter: {char_codes}\n\n")

            # Realizar cifrado
            miwen, shang = JiaMi(char_codes, p, q)
            self.result_box.insert(tk.END, f"Valores Unicode del texto cifrado: {miwen}\n\n")
            self.encrypted_data['Método 2'] = {'miwen': miwen, 'shang': shang, 'prefixes': prefixes, 'p': p, 'q': q}
        
        elif mode == 'Método 3 (Marca de Tiempo)':

            # Agregar marca de tiempo a cada codificación Unicode
            unicode_with_timestamps, timestamps = add_timestamp_to_unicode(input_text)
            self.result_box.insert(tk.END, f"Codificación Unicode con marcas de tiempo (entero): {unicode_with_timestamps}\n\n")
            self.result_box.insert(tk.END, f"Marca de tiempo para cada carácter: {timestamps}\n\n")

            # Realizar cifrado
            miwen, shang = JiaMi(unicode_with_timestamps, p, q)
            self.result_box.insert(tk.END, f"Valores Unicode del texto cifrado: {miwen}\n\n")
        
        # Almacenar datos cifrados
            self.encrypted_data['Método 3'] = {'p': p,'q': q,'miwen': miwen,'shang': shang,'timestamps': timestamps  # Almacenar marca de tiempo para cada carácter
                                          }
        else:
            messagebox.showwarning("Error de Modo", "No se seleccionó un método de etiqueta válido.")
            return

    def on_decrypt(self):
        input_text = self.entry.get().strip()  # Obtener contenido del cuadro de entrada y eliminar espacios iniciales/finales

        if not input_text:
            messagebox.showwarning("Error de Entrada", "Por favor ingrese una cadena para cifrar.")
            return
        
        mode = self.mode_var.get()

        if mode == 'Método 1 (Letras Aleatorias)':
            data = self.encrypted_data.get('Método 1')
            if not data:
                messagebox.showwarning("Error de Descifrado", "Datos cifrados no encontrados. Por favor realice el cifrado primero.")
                return
            miwen = data['miwen']
            shang = data['shang']
            p = data['p']
            q = data['q']
        
            # Realizar descifrado
            decrypted_chars = JieMi(miwen, p, q, shang)
            # Obtener rango de letras
            start = self.letter_start.get()
            end = self.letter_end.get()

            if start > end:
                messagebox.showwarning("Error de Rango", "La letra inicial no puede ser mayor que la letra final.")
                return

            letter_range = get_reduced_alphabet(start, end)

            # Filtrar combinaciones de descifrado válidas
            valid_combinations = filter_decrypt_combinations(decrypted_chars, letter_range)

            # Eliminar sufijos de letras
            cleaned_combinations = [remove_letters_from_string(s) for s in valid_combinations]

            # Mostrar resultados de descifrado
            self.result_box.insert(tk.END, "=== Resultados de Descifrado ===\n\n")
            self.result_box.insert(tk.END, f"Claves p y q utilizadas: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"Todas las soluciones descifradas: {decrypted_chars}\n\n")

            if valid_combinations:
                self.result_box.insert(tk.END, f"Combinaciones de solución válidas: {', '.join(valid_combinations)}\n\n")
                self.result_box.insert(tk.END, f"Cadena descifrada (sin sufijo de letra): {', '.join(cleaned_combinations)}\n\n")
            else:
                self.result_box.insert(tk.END, "No se encontraron combinaciones de solución válidas.\n\n")

        elif mode == 'Método 2 (Secuencia y Suma de Verificación)':
                
            data = self.encrypted_data.get('Método 2')
            if not data:
                messagebox.showwarning("Error de Descifrado", "Datos cifrados no encontrados. Por favor realice el cifrado primero.")
                return
            miwen = data['miwen']
            shang = data['shang']
            prefixes = data['prefixes']
            p = data['p']
            q = data['q']

                # Realizar descifrado
            decrypted_chars = JieMi(miwen, p, q, shang)

            # Filtrar combinaciones de descifrado válidas
            valid_combinations = combine_and_verify(prefixes, decrypted_chars)

            # Mostrar resultados de descifrado
            self.result_box.insert(tk.END, "=== Resultados de Descifrado ===\n\n")
            self.result_box.insert(tk.END, f"Claves p y q utilizadas: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"Todas las soluciones descifradas: {decrypted_chars}\n\n")
            self.result_box.insert(tk.END, f"Combinaciones de solución válidas: {valid_combinations}\n\n")
        
        elif mode == 'Método 3 (Marca de Tiempo)':
            data = self.encrypted_data.get('Método 3')
            if not data:
                messagebox.showwarning("Error de Descifrado", "Datos cifrados no encontrados. Por favor realice el cifrado primero.")
                return
            p = data['p']
            q = data['q']
            miwen = data['miwen']
            shang = data['shang']
            original_timestamps = data['timestamps']
        
            # Realizar descifrado
            decrypted_chars = JieMi(miwen, p, q, shang)

            self.result_box.insert(tk.END, "=== Proceso de Descifrado ===\n\n")
            self.result_box.insert(tk.END, f"Claves p y q utilizadas: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"Valores Unicode descifrados con marcas de tiempo: {decrypted_chars}\n\n")

            # Comparar y extraer caracteres correctos
            valid_chars_with_timestamps, valid_chars ,all_valid_combinations= verify_and_extract_characters(original_timestamps, decrypted_chars)

            if valid_chars_with_timestamps:
                # Mostrar caracteres coincidentes exitosamente (con marcas de tiempo)
                flattened_valid_chars_with_ts = [item for sublist in valid_chars_with_timestamps for item in sublist]
                self.result_box.insert(tk.END, f"Caracteres coincidentes exitosamente (con marcas de tiempo): {', '.join(flattened_valid_chars_with_ts)}\n\n")
        
                # Mostrar caracteres después de eliminar marcas de tiempo
                flattened_valid_chars = [item for sublist in valid_chars for item in sublist]
                self.result_box.insert(tk.END, f"Caracteres después de eliminar marcas de tiempo: {', '.join(flattened_valid_chars)}\n\n")
        
                # Mostrar todas las combinaciones de descifrado posibles
                self.result_box.insert(tk.END, f"Combinaciones de solución válidas: {', '.join(all_valid_combinations)}\n\n")
            else:
                self.result_box.insert(tk.END, "No se encontraron combinaciones de solución coincidentes.\n\n")
           
        else:
            messagebox.showwarning("Error de Modo", "No se seleccionó un método de etiqueta válido.")
            return

def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()